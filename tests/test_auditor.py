import json
import socket
from datetime import datetime, timezone

import pytest

from main import (
    SecurityAuditor,
    apply_env_overrides,
    days_until_expiry,
    is_spf_record,
    parse_dmarc_tags,
    parse_spf_mechanism,
)


@pytest.fixture(autouse=True)
def clean_perimguard_env(monkeypatch):
    """Evita que variables del entorno real contaminen los tests."""
    monkeypatch.delenv("PERIMGUARD_TARGET_DOMAIN", raising=False)
    monkeypatch.delenv("PERIMGUARD_WEB_HOSTS", raising=False)


def make_auditor(zone, **overrides):
    """Crea un auditor cuyo DNS TXT sale de un dict {nombre: [registros]}."""
    config = {"target_domain": "example.com", "web_hosts": [], **overrides}
    auditor = SecurityAuditor(config=config)
    auditor._resolve_txt = lambda name: list(zone.get(name.lower().rstrip("."), []))
    return auditor


# --------------------------------------------------------------------------
# Parseo de mecanismos SPF (incluye regresión del bug del rango [+-~?])
# --------------------------------------------------------------------------

@pytest.mark.parametrize(
    "token, expected",
    [
        ("-all", None),
        ("~all", None),
        ("ip4:192.0.2.1", None),
        ("ip6:2001:db8::/32", None),
        ("exp=explain.example.com", None),
        ("xyz", None),
        ("aaaa", None),
        ("a", ("a", None)),
        ("+a", ("a", None)),
        ("a/24", ("a", None)),
        ("a:mail.example.com/24", ("a", None)),
        ("-mx/24", ("mx", None)),
        ("mx:mail.example.com", ("mx", None)),
        ("ptr", ("ptr", None)),
        ("exists:%{i}.example.com", ("exists", None)),
        ("~include:Foo.com", ("include", "foo.com")),
        ("INCLUDE:B.COM", ("include", "b.com")),
        ("redirect=_spf.example.com", ("redirect", "_spf.example.com")),
    ],
)
def test_parse_spf_mechanism(token, expected):
    assert parse_spf_mechanism(token) == expected


@pytest.mark.parametrize(
    "txt, expected",
    [
        ("v=spf1 -all", True),
        ("V=SPF1", True),
        ("v=spf10 -all", False),
        ("google-site-verification=abc", False),
    ],
)
def test_is_spf_record(txt, expected):
    assert is_spf_record(txt) is expected


# --------------------------------------------------------------------------
# Cálculo recursivo de lookups SPF
# --------------------------------------------------------------------------

def test_spf_recursive_count():
    zone = {
        "example.com": ["v=spf1 include:_spf.proveedor.com mx -all"],
        "_spf.proveedor.com": ["v=spf1 ip4:203.0.113.0/24 a -all"],
    }
    lookups, errors = make_auditor(zone)._count_spf_lookups("example.com")
    assert (lookups, errors) == (3, [])  # include + mx + a (anidado)


def test_spf_cidr_mechanisms_are_counted():
    zone = {"example.com": ["v=spf1 a/24 mx/24 -all"]}
    lookups, errors = make_auditor(zone)._count_spf_lookups("example.com")
    assert (lookups, errors) == (2, [])


@pytest.mark.parametrize("qualifier", ["-", "~", "+", "?"])
def test_spf_all_and_ip_do_not_consume_lookups(qualifier):
    zone = {"example.com": [f"v=spf1 ip4:192.0.2.1 ip6:2001:db8::/32 {qualifier}all"]}
    assert make_auditor(zone)._count_spf_lookups("example.com") == (0, [])


def test_spf_macro_include_is_counted_but_not_followed():
    zone = {"example.com": ["v=spf1 include:%{d}.spf.example.net -all"]}
    assert make_auditor(zone)._count_spf_lookups("example.com") == (1, [])


def test_spf_redirect_ignored_when_all_present():
    zone = {"example.com": ["v=spf1 redirect=otro.com -all"]}
    assert make_auditor(zone)._count_spf_lookups("example.com") == (0, [])


def test_spf_redirect_followed_without_all():
    zone = {
        "example.com": ["v=spf1 redirect=_spf.example.net"],
        "_spf.example.net": ["v=spf1 a mx -all"],
    }
    assert make_auditor(zone)._count_spf_lookups("example.com") == (3, [])


def test_spf_diamond_is_legit_not_a_loop():
    """El mismo dominio incluido desde dos ramas NO es un bucle y cuenta dos veces."""
    zone = {
        "example.com": ["v=spf1 include:b.example.com include:c.example.com -all"],
        "b.example.com": ["v=spf1 include:d.example.com -all"],
        "c.example.com": ["v=spf1 include:d.example.com -all"],
        "d.example.com": ["v=spf1 ip4:192.0.2.1 -all"],
    }
    lookups, errors = make_auditor(zone)._count_spf_lookups("example.com")
    assert errors == []
    assert lookups == 4  # b, d, c, d


def test_spf_circular_include_detected():
    zone = {
        "example.com": ["v=spf1 include:b.example.com -all"],
        "b.example.com": ["v=spf1 include:example.com -all"],
    }
    _, errors = make_auditor(zone)._count_spf_lookups("example.com")
    assert len(errors) == 1
    assert "circular" in errors[0]
    assert "example.com -> b.example.com -> example.com" in errors[0]


def test_spf_self_include_detected():
    zone = {"example.com": ["v=spf1 include:example.com -all"]}
    _, errors = make_auditor(zone)._count_spf_lookups("example.com")
    assert any("circular" in e for e in errors)


def test_spf_missing_include_target_is_error():
    zone = {"example.com": ["v=spf1 include:no-existe.example.net -all"]}
    _, errors = make_auditor(zone)._count_spf_lookups("example.com")
    assert any("Sin registro SPF en no-existe.example.net" in e for e in errors)


def test_spf_case_insensitive():
    zone = {
        "example.com": ["V=SPF1 INCLUDE:B.EXAMPLE.COM -ALL"],
        "b.example.com": ["v=spf1 a -all"],
    }
    assert make_auditor(zone)._count_spf_lookups("example.com") == (2, [])


# ---- audit_spf (resultado final) ------------------------------------------

def test_audit_spf_passes_with_exactly_ten_lookups():
    zone = {"example.com": ["v=spf1 " + " ".join(["a"] * 10) + " -all"]}
    auditor = make_auditor(zone)
    auditor.audit_spf()
    assert auditor.results["checks"]["SPF"]["passed"] is True


def test_audit_spf_fails_with_eleven_lookups():
    includes = " ".join(f"include:s{i}.example.com" for i in range(11))
    zone = {"example.com": [f"v=spf1 {includes} -all"]}
    zone.update({f"s{i}.example.com": ["v=spf1 -all"] for i in range(11)})
    auditor = make_auditor(zone)
    auditor.audit_spf()
    assert auditor.results["checks"]["SPF"]["passed"] is False
    assert "límite" in auditor.results["checks"]["SPF"]["details"]


def test_audit_spf_nested_lookups_exceed_limit_even_if_direct_ones_do_not():
    """Solo 2 lookups directos, pero 12 en total al expandir los include."""
    zone = {
        "example.com": ["v=spf1 include:a.example.com include:b.example.com -all"],
        "a.example.com": ["v=spf1 " + " ".join(["a"] * 5) + " -all"],
        "b.example.com": ["v=spf1 " + " ".join(["mx"] * 5) + " -all"],
    }
    auditor = make_auditor(zone)
    auditor.audit_spf()
    assert auditor.results["checks"]["SPF"]["passed"] is False


def test_audit_spf_multiple_records_is_permerror():
    zone = {"example.com": ["v=spf1 -all", "v=spf1 a -all"]}
    auditor = make_auditor(zone)
    auditor.audit_spf()
    check = auditor.results["checks"]["SPF"]
    assert check["passed"] is False
    assert "PermError" in check["details"]


def test_audit_spf_missing_record():
    auditor = make_auditor({})
    auditor.audit_spf()
    assert auditor.results["checks"]["SPF"]["passed"] is False


# --------------------------------------------------------------------------
# DMARC
# --------------------------------------------------------------------------

def dmarc_auditor(record, **overrides):
    return make_auditor({"_dmarc.example.com": [record]}, **overrides)


@pytest.mark.parametrize(
    "policy, minimum, expected",
    [
        ("reject", "quarantine", True),      # más estricta que el mínimo: PASS
        ("quarantine", "quarantine", True),
        ("none", "quarantine", False),
        ("quarantine", "reject", False),
        ("reject", "reject", True),
        ("none", "none", True),
    ],
)
def test_dmarc_policy_hierarchy(policy, minimum, expected):
    auditor = dmarc_auditor(f"v=DMARC1; p={policy}", min_dmarc_policy=minimum)
    auditor.audit_dmarc()
    assert auditor.results["checks"]["DMARC"]["passed"] is expected


def test_dmarc_pct_below_minimum_fails():
    auditor = dmarc_auditor("v=DMARC1; p=reject; pct=10")
    auditor.audit_dmarc()
    assert auditor.results["checks"]["DMARC"]["passed"] is False


def test_dmarc_pct_custom_minimum_passes():
    auditor = dmarc_auditor("v=DMARC1; p=reject; pct=10", min_dmarc_pct=10)
    auditor.audit_dmarc()
    assert auditor.results["checks"]["DMARC"]["passed"] is True


def test_dmarc_pct_defaults_to_100():
    auditor = dmarc_auditor("v=DMARC1; p=quarantine; rua=mailto:dmarc@example.com")
    auditor.audit_dmarc()
    assert auditor.results["checks"]["DMARC"]["passed"] is True


@pytest.mark.parametrize(
    "record",
    [
        "v=DMARC1; rua=mailto:dmarc@example.com",   # sin p=
        "v=DMARC1; p=banana",                        # p inválido
        "v=DMARC1; p=reject; pct=abc",               # pct no numérico
        "v=DMARC1; p=reject; pct=150",               # pct fuera de rango
    ],
)
def test_dmarc_malformed_records_fail(record):
    auditor = dmarc_auditor(record)
    auditor.audit_dmarc()
    assert auditor.results["checks"]["DMARC"]["passed"] is False


def test_dmarc_missing_record_fails():
    auditor = make_auditor({})
    auditor.audit_dmarc()
    assert auditor.results["checks"]["DMARC"]["passed"] is False


def test_dmarc_multiple_records_fail():
    zone = {"_dmarc.example.com": ["v=DMARC1; p=reject", "v=DMARC1; p=none"]}
    auditor = make_auditor(zone)
    auditor.audit_dmarc()
    assert auditor.results["checks"]["DMARC"]["passed"] is False


def test_parse_dmarc_tags():
    tags = parse_dmarc_tags("v=DMARC1; p=Reject ; pct=50;rua=mailto:a@example.com")
    assert tags["p"] == "Reject"
    assert tags["pct"] == "50"
    assert tags["rua"] == "mailto:a@example.com"


def test_invalid_min_policy_in_config_raises():
    with pytest.raises(ValueError):
        SecurityAuditor(config={"target_domain": "example.com", "min_dmarc_policy": "strict"})


# --------------------------------------------------------------------------
# TLS y orquestación
# --------------------------------------------------------------------------

def test_days_until_expiry():
    now = datetime(2029, 12, 22, 0, 0, 0, tzinfo=timezone.utc)
    expiry, days = days_until_expiry("Jan  1 00:00:00 2030 GMT", now=now)
    assert days == 10
    assert expiry.year == 2030


def test_tls_connection_error_is_recorded_as_failure(monkeypatch):
    def boom(*args, **kwargs):
        raise OSError("sin conexión")

    monkeypatch.setattr(socket, "create_connection", boom)
    auditor = make_auditor({})
    auditor.audit_tls("example.com")
    check = auditor.results["checks"]["TLS_example.com"]
    assert check["passed"] is False
    assert "sin conexión" in check["details"]
    assert auditor.results["passed"] is False


def test_run_all_exit_code_zero_and_json_report(tmp_path):
    zone = {
        "example.com": ["v=spf1 -all"],
        "_dmarc.example.com": ["v=DMARC1; p=reject"],
    }
    out = tmp_path / "report.json"
    assert make_auditor(zone).run_all(str(out)) == 0
    data = json.loads(out.read_text(encoding="utf-8"))
    assert data["passed"] is True
    assert data["summary"] == {"total": 2, "failed": []}


def test_run_all_exit_code_one_when_something_fails(tmp_path):
    out = tmp_path / "report.json"
    assert make_auditor({}).run_all(str(out)) == 1
    data = json.loads(out.read_text(encoding="utf-8"))
    assert data["passed"] is False
    assert sorted(data["summary"]["failed"]) == ["DMARC", "SPF"]


# --------------------------------------------------------------------------
# Sobrescritura por variables de entorno
# --------------------------------------------------------------------------

def test_env_target_domain_overrides_config_dict(monkeypatch):
    monkeypatch.setenv("PERIMGUARD_TARGET_DOMAIN", "  Prod.Example.NET. ")
    auditor = SecurityAuditor(config={"target_domain": "example.com"})
    assert auditor.domain == "prod.example.net"
    assert auditor.results["target_domain"] == "prod.example.net"


def test_env_target_domain_overrides_config_file(monkeypatch, tmp_path):
    cfg = tmp_path / "config.json"
    cfg.write_text(json.dumps({"target_domain": "example.com"}), encoding="utf-8")
    monkeypatch.setenv("PERIMGUARD_TARGET_DOMAIN", "real.example.org")
    auditor = SecurityAuditor(config_path=str(cfg))
    assert auditor.domain == "real.example.org"
    assert auditor.web_hosts == ["real.example.org"]  # sin web_hosts en config: por defecto, el dominio


def test_env_target_domain_works_without_domain_in_config(monkeypatch):
    monkeypatch.setenv("PERIMGUARD_TARGET_DOMAIN", "only-env.example.org")
    assert SecurityAuditor(config={}).domain == "only-env.example.org"


def test_env_web_hosts_override_config(monkeypatch):
    monkeypatch.setenv("PERIMGUARD_WEB_HOSTS", "www.example.com, app.example.com ,, ")
    auditor = SecurityAuditor(config={"target_domain": "example.com", "web_hosts": ["viejo.example.com"]})
    assert auditor.web_hosts == ["www.example.com", "app.example.com"]


def test_empty_env_values_are_ignored(monkeypatch):
    """GitHub Actions pasa cadenas vacías cuando el secreto/variable no existe."""
    monkeypatch.setenv("PERIMGUARD_TARGET_DOMAIN", "   ")
    monkeypatch.setenv("PERIMGUARD_WEB_HOSTS", "")
    auditor = SecurityAuditor(config={"target_domain": "example.com", "web_hosts": ["www.example.com"]})
    assert auditor.domain == "example.com"
    assert auditor.web_hosts == ["www.example.com"]


def test_config_is_used_as_is_without_env():
    auditor = SecurityAuditor(config={"target_domain": "example.com"})
    assert auditor.domain == "example.com"
    assert auditor.web_hosts == ["example.com"]


def test_env_domain_is_the_one_actually_queried(monkeypatch):
    monkeypatch.setenv("PERIMGUARD_TARGET_DOMAIN", "prod.example.net")
    zone = {"_dmarc.prod.example.net": ["v=DMARC1; p=reject"]}
    auditor = make_auditor(zone)  # config dice example.com, el entorno manda
    auditor.audit_dmarc()
    assert auditor.results["checks"]["DMARC"]["passed"] is True


def test_apply_env_overrides_is_pure():
    original = {"target_domain": "example.com", "web_hosts": ["a.example.com"]}
    merged = apply_env_overrides(
        original,
        environ={"PERIMGUARD_TARGET_DOMAIN": "x.example.org", "PERIMGUARD_WEB_HOSTS": "x.example.org"},
    )
    assert merged == {"target_domain": "x.example.org", "web_hosts": ["x.example.org"]}
    assert original == {"target_domain": "example.com", "web_hosts": ["a.example.com"]}


def test_default_tls_threshold_is_21_days():
    assert SecurityAuditor(config={"target_domain": "example.com"}).tls_days_limit == 21
