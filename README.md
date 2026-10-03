# PerimGuard

Auditor en Python para vigilar de forma continua la autenticación de correo (SPF, DMARC) y la caducidad de los certificados TLS de un dominio. Pensado para ejecutarse en GitHub Actions sin infraestructura propia.

## Qué comprueba

1. **SPF recursivo (RFC 7208)**
   - Expande `include:` y `redirect=` y cuenta el total de lookups DNS (límite de 10).
   - Cuenta también `a`, `mx`, `ptr` y `exists`, con o sin calificador y con CIDR (`a/24`, `mx/24`).
   - Detecta varios registros SPF (PermError), includes inexistentes y bucles circulares.
   - El mismo dominio incluido desde ramas distintas no se considera bucle, y cuenta cada vez.
2. **DMARC**
   - Compara la política por nivel: `none < quarantine < reject`. Una política más estricta que la mínima pasa.
   - Exige un `pct=` mínimo (por defecto 100). Si falta el tag, se asume 100.
3. **TLS**
   - Conecta al puerto 443 de cada host de `web_hosts`, valida la cadena con el almacén de confianza del sistema y calcula los días hasta la caducidad.
4. **Reporte JSON**
   - Cada ejecución genera `audit_report.json` y devuelve código de salida 0 (todo correcto) o 1 (alguna comprobación falla).

## Configuración

Los valores salen de `config.json`, y las variables de entorno tienen prioridad sobre él.

| Clave en `config.json` | Variable de entorno | Descripción | Por defecto |
|---|---|---|---|
| `target_domain` | `PERIMGUARD_TARGET_DOMAIN` | Dominio a auditar (SPF y DMARC) | `example.com` |
| `web_hosts` | `PERIMGUARD_WEB_HOSTS` (separados por comas) | Hosts a los que se comprueba TLS en el 443 | el propio dominio |
| `tls_min_days_warning` | | Días mínimos de validez del certificado | 21 |
| `min_dmarc_policy` | | `none`, `quarantine` o `reject` | `quarantine` |
| `min_dmarc_pct` | | Porcentaje mínimo de `pct=` | 100 |
| `dns_timeout_seconds` | | Timeout de las consultas DNS | 5.0 |
| `tls_timeout_seconds` | | Timeout de la conexión TLS | 10.0 |

Detalles:

- Las variables vacías o con solo espacios se ignoran.
- El `config.json` incluido no define `web_hosts`, así que por defecto se comprueba TLS en el propio dominio. Si defines `web_hosts` en el fichero y cambias el dominio por variable de entorno, define también `PERIMGUARD_WEB_HOSTS`, porque la lista del fichero se seguiría usando.
- Los subdominios que solo sirven correo (por ejemplo `send.`) no deben ir en `web_hosts`: normalmente no escuchan en el 443.

## Uso local

```bash
python -m venv .venv
source .venv/bin/activate
pip install -r requirements-dev.txt
pytest
PERIMGUARD_TARGET_DOMAIN=tu-dominio.com python main.py
```

Opciones: `--config RUTA` y `--output RUTA`.

## Despliegue en GitHub

```bash
git init -b main
git add .
git commit -m "feat: initial commit of PerimGuard"
git remote add origin git@github.com:TU-USUARIO/perim-guard.git
git push -u origin main
```

Crea antes un repositorio vacío llamado `perim-guard` en GitHub, sin README ni .gitignore, y cambia `TU-USUARIO` por tu usuario. Con la CLI de GitHub puedes hacerlo todo desde la carpeta del proyecto:

```bash
gh repo create perim-guard --private --source=. --remote=origin --push
```

### Configurar tu dominio real (sin ponerlo en el código)

En el repositorio, ve a Settings, Secrets and variables, Actions, y crea:

- `TARGET_DOMAIN`: tu dominio. Mejor como secreto (Secrets), porque GitHub lo enmascara en los logs. Si lo creas como variable (Variables), también funciona, pero se verá en claro.
- `WEB_HOSTS` (opcional): hosts para TLS separados por comas.

Si ambos existen, el secreto tiene prioridad sobre la variable. Si no defines ninguno, el workflow audita el dominio de `config.json` (`example.com`), que normalmente fallará en DMARC. Define `TARGET_DOMAIN` antes de la primera ejecución.

### Cómo funciona el workflow

El workflow `.github/workflows/audit.yml`:

- En cada push a `main` y en cada pull request ejecuta solo `pytest`.
- Cada lunes a las 06:00 UTC y al lanzarlo a mano (pestaña Actions, Run workflow) ejecuta `pytest` y, si pasa, la auditoría real.
- Guarda el reporte como artefacto `audit-report` durante 14 días.

### Privacidad

- Aunque el dominio no esté en el código, `audit_report.json` lo contiene en claro. En un repositorio público, cualquier usuario con sesión en GitHub puede descargar los artefactos. Si no quieres exponerlo, usa un repositorio privado o elimina el paso "Guardar reporte JSON" del workflow.
- Tu dominio ya es público por el DNS y por Certificate Transparency, así que esto reduce la exposición, pero no la elimina.

GitHub desactiva automáticamente los workflows programados de un repositorio público tras 60 días sin actividad. Si la vigilancia es importante, reactívalo de vez en cuando o haz algún commit.

## Limitaciones conocidas

- No expande macros SPF (`%{d}`): cuenta el mecanismo, pero no lo sigue.
- No cuenta las resoluciones adicionales que dispara `mx` (consultas a cada MX) ni los "void lookups".
- No comprueba DKIM, CAA, MTA-STS ni Certificate Transparency.
- Usa el resolvedor DNS del sistema, sin validación DNSSEC.
