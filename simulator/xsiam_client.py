"""
xsiam_client.py — Cliente para el HTTP Log Collector de Cortex XSIAM.

Basado en el ejemplo oficial que entrega el tenant ("View Example"):

    POST https://api-<tenant>.xdr.<region>.paloaltonetworks.com/logs/v1/event
    Authorization: <api_key>
    Content-Type: text/plain
    Body: un evento por línea (separados por \n)

Añade sobre ese ejemplo lo que hace falta para un laboratorio:
  - batching (no mandar 1 request por evento)
  - gzip opcional (si el colector se creó con compresión gzip)
  - reintentos con backoff ante 429 / 5xx
  - modo --dry-run para ver exactamente qué se enviaría (útil para depurar parsers
    sin quemar cuota de ingesta)
  - contadores para el reporte de laboratorio

Uso típico:
    from xsiam_client import XsiamCollector, load_config
    cfg = load_config("config.json")
    c = XsiamCollector.from_config(cfg, "waf")
    c.send(["CEF:0|...", "CEF:0|..."])
    c.flush()
"""

from __future__ import annotations

import gzip
import json
import os
import sys
import time
from dataclasses import dataclass, field
from typing import Iterable

# ── HTTP: requests si está, si no la librería estándar ─────────────────────
#
# El laboratorio no debe depender de que pip funcione en la máquina de cada
# alumno. Si `requests` está instalado se usa (es mejor: reutiliza conexiones);
# si no, se cae a urllib con un envoltorio mínimo que imita la misma interfaz.
# El resto del archivo no nota la diferencia.

import urllib.error
import urllib.request

try:
    import requests
    HTTP_BACKEND = "requests"
    NETWORK_ERRORS = (requests.RequestException, OSError, TimeoutError)
except ImportError:
    requests = None
    HTTP_BACKEND = "urllib (librería estándar)"
    NETWORK_ERRORS = (urllib.error.URLError, OSError, TimeoutError)


class _Response:
    """Lo mínimo que el resto del código le pide a una respuesta HTTP."""

    __slots__ = ("status_code", "text", "headers")

    def __init__(self, status_code, text, headers):
        self.status_code = status_code
        self.text = text
        self.headers = headers


class _UrllibSession:
    """Reemplazo de requests.Session con solo la librería estándar."""

    def post(self, url, headers=None, data=None, timeout=30):
        if isinstance(data, str):
            data = data.encode("utf-8")
        req = urllib.request.Request(
            url, data=data, headers=headers or {}, method="POST"
        )
        try:
            with urllib.request.urlopen(req, timeout=timeout) as res:
                body = res.read().decode("utf-8", "replace")
                return _Response(res.status, body, res.headers)
        except urllib.error.HTTPError as err:
            # 4xx/5xx: no es un fallo de red, es una respuesta del servidor.
            body = ""
            try:
                body = err.read().decode("utf-8", "replace")
            except Exception:
                pass
            return _Response(err.code, body, err.headers or {})

    def close(self):
        pass


def _new_session():
    return requests.Session() if requests else _UrllibSession()


# --------------------------------------------------------------------------
# Configuración
# --------------------------------------------------------------------------

DEFAULT_CONFIG_PATHS = ["config.json", "simulator/config.json", "../config.json"]

# Variables de entorno que pisan el archivo de config (útil en clase: cada
# alumno exporta sus llaves y no toca el repo)
ENV_URL = "XSIAM_URL"
ENV_KEY_TPL = "XSIAM_KEY_{}"  # XSIAM_KEY_WAF, XSIAM_KEY_FW, XSIAM_KEY_EDR, XSIAM_KEY_AUTH
ENV_TEAMS = "XSIAM_TEAMS_JSON"  # la sección `teams` completa, como JSON en una variable


def load_config(path: str | None = None) -> dict:
    """Carga config.json. Si no existe, arma una config solo desde variables de entorno."""
    candidates = [path] if path else DEFAULT_CONFIG_PATHS
    for p in candidates:
        if p and os.path.isfile(p):
            with open(p, "r", encoding="utf-8") as fh:
                cfg = json.load(fh)
            break
    else:
        cfg = {"tenant_api_url": "", "collectors": {}}

    # Overrides por entorno
    if os.getenv(ENV_URL):
        cfg["tenant_api_url"] = os.environ[ENV_URL]
    # La sección `teams` puede venir entera en una variable de entorno. Así el
    # instructor trabaja desde un Codespace sin que ninguna API key toque el repo.
    if os.getenv(ENV_TEAMS):
        try:
            cfg["teams"] = json.loads(os.environ[ENV_TEAMS])
        except json.JSONDecodeError as exc:
            raise ValueError(f"{ENV_TEAMS} no es JSON válido: {exc}") from exc

    cfg.setdefault("collectors", {})
    for name in ("waf", "fw", "edr", "auth"):
        env_key = os.getenv(ENV_KEY_TPL.format(name.upper()))
        if env_key:
            cfg["collectors"].setdefault(name, {})
            cfg["collectors"][name]["api_key"] = env_key
    return cfg


def list_teams(cfg: dict) -> list[str]:
    """Nombres de equipo definidos en la sección `teams` de la config."""
    return sorted((cfg.get("teams") or {}).keys())


def resolve_team_config(cfg: dict, team: str | None) -> dict:
    """Devuelve una config de un solo equipo, lista para CollectorSet.

    Sin `--team`, se usa la sección `collectors` de nivel superior (el modo del
    alumno: sus 4 colectores y nada más). Con `--team`, se toma la entrada
    correspondiente de `teams`, heredando `tenant_api_url` si el equipo no
    define uno propio (caso de tenant compartido).
    """
    if not team:
        return cfg
    teams = cfg.get("teams") or {}
    if team not in teams:
        raise KeyError(
            f"El equipo '{team}' no está en la config. Definidos: {list_teams(cfg) or 'ninguno'}"
        )
    entry = teams[team]
    return {
        "tenant_api_url": entry.get("tenant_api_url") or cfg.get("tenant_api_url"),
        "collectors": entry.get("collectors", {}),
        "_variant": entry.get("variant"),
        "_team": team,
    }


# --------------------------------------------------------------------------
# Cliente
# --------------------------------------------------------------------------


@dataclass
class SendStats:
    events: int = 0
    requests: int = 0
    bytes_sent: int = 0
    errors: int = 0
    retries: int = 0
    status_counts: dict = field(default_factory=dict)

    def merge(self, other: "SendStats") -> None:
        self.events += other.events
        self.requests += other.requests
        self.bytes_sent += other.bytes_sent
        self.errors += other.errors
        self.retries += other.retries
        for k, v in other.status_counts.items():
            self.status_counts[k] = self.status_counts.get(k, 0) + v

    def summary(self) -> str:
        kb = self.bytes_sent / 1024.0
        st = ", ".join(f"{k}:{v}" for k, v in sorted(self.status_counts.items())) or "-"
        return (
            f"eventos={self.events}  requests={self.requests}  "
            f"{kb:,.1f} KB  reintentos={self.retries}  errores={self.errors}  [{st}]"
        )


class XsiamCollector:
    """Un colector HTTP de XSIAM (= un dataset destino)."""

    def __init__(
        self,
        name: str,
        url: str,
        api_key: str,
        *,
        compress: bool = False,
        batch_size: int = 500,
        max_batch_bytes: int = 4 * 1024 * 1024,  # el límite duro es ~5 MB por request
        dry_run: bool = False,
        dry_run_dir: str = "out",
        timeout: int = 30,
        verbose: bool = True,
    ):
        self.name = name
        self.url = url
        self.api_key = api_key
        self.compress = compress
        self.batch_size = batch_size
        self.max_batch_bytes = max_batch_bytes
        self.dry_run = dry_run
        self.dry_run_dir = dry_run_dir
        self.timeout = timeout
        self.verbose = verbose

        self._buffer: list[str] = []
        self._buffer_bytes = 0
        self.stats = SendStats()
        self._session = None if dry_run else _new_session()
        self._dry_fh = None

        if dry_run:
            os.makedirs(dry_run_dir, exist_ok=True)
            self._dry_fh = open(
                os.path.join(dry_run_dir, f"{name}.log"), "w", encoding="utf-8"
            )

    # -- construcción -------------------------------------------------------

    @classmethod
    def from_config(cls, cfg: dict, name: str, **kwargs) -> "XsiamCollector":
        col = (cfg.get("collectors") or {}).get(name)
        if not col:
            raise KeyError(
                f"No hay colector '{name}' en la config. "
                f"Define collectors.{name}.api_key o exporta {ENV_KEY_TPL.format(name.upper())}."
            )
        url = col.get("url") or cfg.get("tenant_api_url")
        if not url:
            raise ValueError("Falta 'tenant_api_url' en la config (o la variable XSIAM_URL).")
        return cls(
            name=name,
            url=url,
            api_key=col.get("api_key", ""),
            compress=bool(col.get("compress", False)),
            **kwargs,
        )

    # -- envío --------------------------------------------------------------

    def send(self, events: Iterable[str]) -> None:
        """Encola eventos. Se envían automáticamente al llenar el batch."""
        for ev in events:
            line = ev if isinstance(ev, str) else json.dumps(ev, ensure_ascii=False)
            line = line.replace("\n", " ").replace("\r", " ")
            self._buffer.append(line)
            self._buffer_bytes += len(line) + 1
            if (
                len(self._buffer) >= self.batch_size
                or self._buffer_bytes >= self.max_batch_bytes
            ):
                self.flush()

    def send_one(self, event) -> None:
        self.send([event])

    def flush(self) -> None:
        if not self._buffer:
            return
        # IMPORTANTE: el colector HTTP espera un evento por línea.
        body = "\n".join(self._buffer)
        n = len(self._buffer)
        self._buffer = []
        self._buffer_bytes = 0

        if self.dry_run:
            self._dry_fh.write(body + "\n")
            self.stats.events += n
            self.stats.requests += 1
            self.stats.bytes_sent += len(body.encode("utf-8"))
            self.stats.status_counts["dry-run"] = (
                self.stats.status_counts.get("dry-run", 0) + 1
            )
            return

        self._post_with_retry(body, n)

    def _post_with_retry(self, body: str, n_events: int, max_attempts: int = 5) -> None:
        headers = {"Authorization": self.api_key, "Content-Type": "text/plain"}
        data = body.encode("utf-8")
        if self.compress:
            data = gzip.compress(data)
            headers["Content-Encoding"] = "gzip"

        delay = 1.0
        for attempt in range(1, max_attempts + 1):
            try:
                res = self._session.post(
                    url=self.url, headers=headers, data=data, timeout=self.timeout
                )
            except NETWORK_ERRORS as exc:
                self.stats.retries += 1
                if attempt == max_attempts:
                    self.stats.errors += n_events
                    self._log(f"[{self.name}] ERROR de red tras {attempt} intentos: {exc}")
                    return
                time.sleep(delay)
                delay = min(delay * 2, 30)
                continue

            code = res.status_code
            self.stats.status_counts[code] = self.stats.status_counts.get(code, 0) + 1

            if 200 <= code < 300:
                self.stats.events += n_events
                self.stats.requests += 1
                self.stats.bytes_sent += len(data)
                return

            if code in (429, 500, 502, 503, 504):
                self.stats.retries += 1
                if attempt == max_attempts:
                    break
                try:
                    wait = float((res.headers or {}).get("Retry-After", delay) or delay)
                except (TypeError, ValueError):
                    wait = delay
                self._log(f"[{self.name}] HTTP {code}; reintento {attempt} en {wait:.0f}s")
                time.sleep(wait)
                delay = min(delay * 2, 30)
                continue

            # 401/403 = API key mala o colector deshabilitado. 400 = body inválido.
            self.stats.errors += n_events
            self._log(
                f"[{self.name}] HTTP {code} — {res.text[:300]}\n"
                f"          Revisa: API key del colector, URL del tenant, y que el "
                f"colector esté ENABLED."
            )
            return

        self.stats.errors += n_events
        self._log(f"[{self.name}] Se agotaron los reintentos ({n_events} eventos perdidos).")

    # -- utilidades ---------------------------------------------------------

    def test(self) -> bool:
        """Envía un evento canario. Devuelve True si el tenant lo aceptó."""
        canary = json.dumps(
            {
                "lab": "xsiam-deep-dive",
                "collector": self.name,
                "check": "connectivity",
                "timestamp": int(time.time() * 1000),
            }
        )
        before_err = self.stats.errors
        self.send_one(canary)
        self.flush()
        ok = self.stats.errors == before_err
        self._log(f"[{self.name}] {'OK' if ok else 'FALLO'} — {self.stats.summary()}")
        return ok

    def close(self) -> None:
        self.flush()
        if self._dry_fh:
            self._dry_fh.close()
        if self._session:
            self._session.close()

    def _log(self, msg: str) -> None:
        if self.verbose:
            print(msg, file=sys.stderr)

    def __enter__(self):
        return self

    def __exit__(self, *exc):
        self.close()


class CollectorSet:
    """Maneja los 4 colectores del laboratorio como una unidad."""

    NAMES = ("waf", "fw", "edr", "auth")

    def __init__(self, cfg: dict, *, dry_run: bool = False, dry_run_dir: str = "out",
                 only: list[str] | None = None, verbose: bool = True):
        self.collectors: dict[str, XsiamCollector] = {}
        wanted = only or list(self.NAMES)
        for name in wanted:
            try:
                self.collectors[name] = XsiamCollector.from_config(
                    cfg, name, dry_run=dry_run, dry_run_dir=dry_run_dir, verbose=verbose
                )
            except (KeyError, ValueError) as exc:
                if dry_run:
                    # En dry-run no hace falta API key: solo escribimos a disco.
                    self.collectors[name] = XsiamCollector(
                        name=name, url="dry-run", api_key="",
                        dry_run=True, dry_run_dir=dry_run_dir, verbose=verbose
                    )
                elif verbose:
                    print(f"[aviso] colector '{name}' no configurado: {exc}", file=sys.stderr)

    def __getitem__(self, name: str) -> XsiamCollector:
        return self.collectors[name]

    def __contains__(self, name: str) -> bool:
        return name in self.collectors

    def send(self, name: str, events) -> None:
        if name in self.collectors:
            self.collectors[name].send(events)

    def flush(self) -> None:
        for c in self.collectors.values():
            c.flush()

    def close(self) -> None:
        for c in self.collectors.values():
            c.close()

    def totals(self) -> SendStats:
        t = SendStats()
        for c in self.collectors.values():
            t.merge(c.stats)
        return t

    def report(self) -> str:
        lines = ["", "── Resumen de ingesta ──────────────────────────────────"]
        for name, c in self.collectors.items():
            lines.append(f"  {name:<5} {c.stats.summary()}")
        lines.append(f"  {'TOTAL':<5} {self.totals().summary()}")
        return "\n".join(lines)
