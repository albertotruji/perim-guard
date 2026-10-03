#!/usr/bin/env python3
"""
PerimGuard: auditor de autenticación de correo (SPF recursivo, DMARC)
y caducidad de certificados TLS.
"""

from __future__ import annotations

import argparse
import json
import os
import re
import socket
import ssl
import sys
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional, Tuple

import dns.resolver

DMARC_LEVELS = {"none": 1, "quarantine": 2, "reject": 3}
SPF_QUALIFIERS = "+-~?"
SPF_LOOKUP_LIMIT = 10  # RFC 7208 §4.6.4
ALL_PATTERN = re.compile(r"^[-+~?]?all$", re.IGNORECASE)

# Variables de entorno que tienen prioridad sobre config.json
ENV_TARGET_DOMAIN = "PERIMGUARD_TARGET_DOMAIN"
ENV_WEB_HOSTS = "PERIMGUARD_WEB_HOSTS"  # lista separada por comas


# --------------------------------------------------------------------------
# Utilidades puras (fáciles de testear)
# --------------------------------------------------------------------------

def is_spf_record(txt: str) -> bool:
    t = txt.strip().lower()
    return t == "v=spf1" or t.startswith("v=spf1 ")


def parse_spf_mechanism(token: str) -> Optional[Tuple[str, Optional[str]]]:
    """
    Devuelve (tipo, destino) si el token consume un lookup DNS, o None si no.
    Tipos: include, redirect, a, mx, ptr, exists.
    'destino' solo se devuelve para include/redirect (los que se recorren).
    """
    t = token.strip().lower()
    if t and t[0] in SPF_QUALIFIERS:
        t = t[1:]
    if t.startswith("include:"):
        return "include", t[len("include:"):]
    if t.startswith("redirect="):
        return "redirect", t[len("redirect="):]
    if t.startswith("exists:"):
        return "exists", None
    for name in ("a", "mx", "ptr"):
        if t == name or t.startswith((name + ":", name + "/")):
            return name, None
    return None


def parse_dmarc_tags(record: str) -> Dict[str, str]:
    tags: Dict[str, str] = {}
    for part in record.split(";"):
        if "=" in part:
            key, value = part.split("=", 1)
            tags[key.strip().lower()] = value.strip()
    return tags


def apply_env_overrides(config: Dict[str, Any], environ: Optional[Any] = None) -> Dict[str, Any]:
    """
    Devuelve una copia de 'config' con las variables de entorno aplicadas por encima.
    Los valores vacíos o solo con espacios se ignoran (GitHub Actions pasa una cadena
    vacía cuando la variable o el secreto no están definidos).
    """
    environ = os.environ if environ is None else environ
    merged = dict(config)

    domain = environ.get(ENV_TARGET_DOMAIN, "").strip()
    if domain:
        merged["target_domain"] = domain

    hosts = [h.strip() for h in environ.get(ENV_WEB_HOSTS, "").split(",") if h.strip()]
    if hosts:
        merged["web_hosts"] = hosts

    return merged


def days_until_expiry(not_after: str, now: Optional[datetime] = None) -> Tuple[datetime, int]:
    """not_after en formato ASN.1 de getpeercert(), p. ej. 'Jan  1 00:00:00 2030 GMT'."""
    expiry = datetime.fromtimestamp(ssl.cert_time_to_seconds(not_after), timezone.utc)
    now = now or datetime.now(timezone.utc)
    return expiry, (expiry - now).days


# --------------------------------------------------------------------------
# Auditor
# --------------------------------------------------------------------------

class SecurityAuditor:
    def __init__(self, config_path: str = "config.json", config: Optional[Dict[str, Any]] = None):
        if config is None:
            with open(config_path, "r", encoding="utf-8") as f:
                config = json.load(f)
        config = apply_env_overrides(config)
        self.config = config

        self.domain = config["target_domain"].strip().lower().rstrip(".")
        self.web_hosts: List[str] = config.get("web_hosts", [self.domain])
        self.tls_days_limit = int(config.get("tls_min_days_warning", 21))
        self.min_dmarc = str(config.get("min_dmarc_policy", "quarantine")).lower()
        if self.min_dmarc not in DMARC_LEVELS:
            raise ValueError(
                f"min_dmarc_policy inválida: '{self.min_dmarc}' (válidas: {', '.join(DMARC_LEVELS)})"
            )
        self.min_dmarc_pct = int(config.get("min_dmarc_pct", 100))
        self.dns_timeout = float(config.get("dns_timeout_seconds", 5.0))
        self.tls_timeout = float(config.get("tls_timeout_seconds", 10.0))

        self._resolver: Optional[dns.resolver.Resolver] = None
        self._txt_cache: Dict[str, List[str]] = {}

        self.results: Dict[str, Any] = {
            "target_domain": self.domain,
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "passed": True,
            "checks": {},
        }

    # ---- DNS --------------------------------------------------------------

    def _resolve_txt(self, name: str) -> List[str]:
        key = name.lower().rstrip(".")
        if key in self._txt_cache:
            return self._txt_cache[key]
        if self._resolver is None:
            resolver = dns.resolver.Resolver()
            resolver.timeout = self.dns_timeout
            resolver.lifetime = self.dns_timeout
            self._resolver = resolver
        try:
            answers = self._resolver.resolve(key, "TXT")
            records = [b"".join(rd.strings).decode("utf-8", errors="replace") for rd in answers]
        except (dns.resolver.NoAnswer, dns.resolver.NXDOMAIN):
            records = []
        self._txt_cache[key] = records
        return records

    # ---- SPF --------------------------------------------------------------

    def _count_spf_lookups(self, domain: str, path: Tuple[str, ...] = ()) -> Tuple[int, List[str]]:
        """
        Cuenta los lookups DNS de un registro SPF y de todo su árbol de include/redirect.
        Los bucles se detectan solo sobre la RUTA actual (path): el mismo dominio
        incluido desde ramas distintas es legal y cuenta cada vez.
        """
        key = domain.lower().rstrip(".")
        if key in path:
            return 0, [f"Bucle circular: {' -> '.join(path + (key,))}"]
        path = path + (key,)

        spf_records = [r for r in self._resolve_txt(key) if is_spf_record(r)]
        if not spf_records:
            return 0, [f"Sin registro SPF en {key}"]
        if len(spf_records) > 1:
            return 0, [f"PermError: {len(spf_records)} registros SPF en {key}"]

        tokens = spf_records[0].split()[1:]
        has_all = any(ALL_PATTERN.match(t) for t in tokens)  # RFC 7208 §6.1: redirect se ignora si hay 'all'
        lookups = 0
        errors: List[str] = []

        for token in tokens:
            parsed = parse_spf_mechanism(token)
            if parsed is None:
                continue
            kind, target = parsed
            if kind == "redirect" and has_all:
                continue
            lookups += 1
            if kind in ("include", "redirect") and target and "%" not in target:
                sub_lookups, sub_errors = self._count_spf_lookups(target, path)
                lookups += sub_lookups
                errors.extend(sub_errors)
            if lookups > SPF_LOOKUP_LIMIT:
                break  # ya excede el límite: no hace falta seguir recorriendo

        return lookups, errors

    def audit_spf(self) -> None:
        try:
            lookups, errors = self._count_spf_lookups(self.domain)
        except Exception as exc:
            self._record_check("SPF", False, f"Excepción auditando SPF: {exc}")
            return

        if errors:
            self._record_check("SPF", False, "; ".join(errors))
        elif lookups > SPF_LOOKUP_LIMIT:
            self._record_check("SPF", False, f"Supera el límite de {SPF_LOOKUP_LIMIT} lookups DNS (>= {lookups})")
        else:
            self._record_check("SPF", True, f"{lookups}/{SPF_LOOKUP_LIMIT} lookups DNS (recursivos)")

    # ---- DMARC ------------------------------------------------------------

    def audit_dmarc(self) -> None:
        name = f"_dmarc.{self.domain}"
        try:
            records = [r for r in self._resolve_txt(name) if r.strip().lower().startswith("v=dmarc1")]
        except Exception as exc:
            self._record_check("DMARC", False, f"Excepción auditando DMARC: {exc}")
            return

        if not records:
            self._record_check("DMARC", False, f"No se encontró registro DMARC en {name}")
            return
        if len(records) > 1:
            self._record_check("DMARC", False, f"Múltiples registros DMARC en {name}")
            return

        tags = parse_dmarc_tags(records[0])
        policy = tags.get("p", "").lower()
        if policy not in DMARC_LEVELS:
            self._record_check("DMARC", False, f"Tag 'p=' ausente o inválido en: {records[0]}")
            return

        try:
            pct = int(tags.get("pct", "100"))
            if not 0 <= pct <= 100:
                raise ValueError
        except ValueError:
            self._record_check("DMARC", False, f"Valor 'pct=' inválido: {tags.get('pct')}")
            return

        policy_ok = DMARC_LEVELS[policy] >= DMARC_LEVELS[self.min_dmarc]
        pct_ok = pct >= self.min_dmarc_pct
        details = (
            f"p={policy} (mínimo: {self.min_dmarc}) | "
            f"pct={pct} (mínimo: {self.min_dmarc_pct})"
        )
        self._record_check("DMARC", policy_ok and pct_ok, details)

    # ---- TLS --------------------------------------------------------------

    def audit_tls(self, host: str) -> None:
        name = f"TLS_{host}"
        context = ssl.create_default_context()
        try:
            with socket.create_connection((host, 443), timeout=self.tls_timeout) as sock:
                with context.wrap_socket(sock, server_hostname=host) as ssock:
                    cert = ssock.getpeercert()
            expiry, days_left = days_until_expiry(cert["notAfter"])
            passed = days_left >= self.tls_days_limit
            details = (
                f"Caduca el {expiry.strftime('%Y-%m-%d %H:%M UTC')} "
                f"({days_left} días restantes, umbral: {self.tls_days_limit})"
            )
            self._record_check(name, passed, details)
        except Exception as exc:
            self._record_check(name, False, f"Error validando TLS en {host}:443: {exc}")

    # ---- Orquestación -----------------------------------------------------

    def _record_check(self, name: str, passed: bool, details: str) -> None:
        self.results["checks"][name] = {"passed": passed, "details": details}
        if not passed:
            self.results["passed"] = False
        label = "[PASS]" if passed else "[FAIL]"
        print(f"  {label:<7} {name:<28} {details}")

    def run_all(self, output_json: str = "audit_report.json") -> int:
        print(f"[*] Auditoría perimetral de {self.domain}")
        self.audit_spf()
        self.audit_dmarc()
        for host in self.web_hosts:
            self.audit_tls(host)

        failed = [n for n, c in self.results["checks"].items() if not c["passed"]]
        self.results["summary"] = {"total": len(self.results["checks"]), "failed": failed}

        with open(output_json, "w", encoding="utf-8") as f:
            json.dump(self.results, f, indent=2, ensure_ascii=False)
        print(f"[*] Reporte exportado a {output_json}")
        return 0 if self.results["passed"] else 1


def main(argv: Optional[List[str]] = None) -> int:
    parser = argparse.ArgumentParser(description="PerimGuard: auditor perimetral SPF/DMARC/TLS")
    parser.add_argument("--config", default="config.json", help="ruta del archivo de configuración")
    parser.add_argument("--output", default="audit_report.json", help="ruta del reporte JSON")
    args = parser.parse_args(argv)
    return SecurityAuditor(config_path=args.config).run_all(output_json=args.output)


if __name__ == "__main__":
    sys.exit(main())
