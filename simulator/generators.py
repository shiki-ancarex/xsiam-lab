"""
generators.py — Generadores de eventos sintéticos para el laboratorio XSIAM.

Cuatro fuentes, cuatro formatos a propósito distintos, para que los alumnos
tengan que escribir tres tipos de parser/modeling diferentes:

  fuente | formato de salida                    | técnica de parsing en XSIAM
  -------|--------------------------------------|-----------------------------------
  waf    | syslog RFC3164 + CEF                 | CEF nativo o regextract
  fw     | syslog RFC3164 + campos pipe "|"     | regextract + split()  (el más duro)
  edr    | JSON anidado con arrays              | json_extract_scalar / json_extract_array
  auth   | JSON plano-anidado                   | json_extract_scalar

IMPORTANTE: todos los generadores devuelven una tupla (timestamp, linea) para que
el motor de envío pueda ordenar cronológicamente y reproducir en tiempo real.

El "entorno" (hosts, IPs, usuarios, infra del atacante) vive en la clase Env y se
puede variar por equipo con --variant, de modo que cada grupo investiga un
incidente con IOCs distintos y no puede copiar la respuesta del vecino.
"""

from __future__ import annotations

import hashlib
import json
import random
import re
import string
import urllib.parse
from dataclasses import dataclass, field
from datetime import datetime, timedelta, timezone

# --------------------------------------------------------------------------
# Entorno ficticio: ANDINA RETAIL S.A.
# --------------------------------------------------------------------------

ORG = "ANDINA"
DOMAIN = "andinaretail.com"

WORKSTATIONS = [
    ("WKS-VTA-014", "10.20.10.14", "jperez"),
    ("WKS-VTA-027", "10.20.10.27", "mgonzalez"),
    ("WKS-FIN-006", "10.20.11.6", "lramirez"),
    ("WKS-FIN-009", "10.20.11.9", "csuarez"),
    ("WKS-TI-003", "10.20.12.3", "adminti"),
    ("WKS-RRHH-011", "10.20.13.11", "ptorres"),
    ("WKS-LOG-022", "10.20.14.22", "rmendoza"),
    ("WKS-MKT-018", "10.20.15.18", "dvargas"),
]

SERVERS = [
    ("WEB-DMZ-01", "10.20.30.11", "iis"),          # servidor web público — objetivo inicial
    ("WEB-DMZ-02", "10.20.30.12", "iis"),
    ("SRV-FILE-01", "10.20.40.21", "fileserver"),  # joya de la corona: datos de clientes
    ("SRV-SQL-01", "10.20.40.31", "database"),
    ("SRV-DC-01", "10.20.40.5", "domaincontroller"),
    ("SRV-BKP-01", "10.20.40.41", "backup"),
]

USERS = [u for _, _, u in WORKSTATIONS] + [
    "svc_backup", "svc_iis", "svc_sql", "aortega", "administrador",
]

BENIGN_DST = [
    "23.62.99.10", "104.18.32.115", "142.250.79.14", "20.190.159.4",
    "13.107.42.14", "52.96.104.18", "151.101.1.140", "34.107.221.82",
]

USER_AGENTS_OK = [
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/126.0 Safari/537.36",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.4 Safari/605.1.15",
    "Mozilla/5.0 (iPhone; CPU iPhone OS 17_5 like Mac OS X) AppleWebKit/605.1.15 Mobile/15E148",
    "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/125.0 Safari/537.36",
]

# Rutas legítimas. Muchas llevan parámetros: si solo los ataques tuvieran
# payload, detectarlos sería trivial y no se aprendería nada.
WEB_PATHS_OK = [
    "/", "/catalogo", "/catalogo/electrodomesticos", "/producto/ver?id={id}",
    "/carrito", "/checkout", "/api/v1/precios?sku={sku}",
    "/api/v1/stock?sku={sku}&sucursal={suc}", "/cuenta/login",
    "/cuenta/pedidos?pagina={pag}", "/static/app.js", "/static/estilos.css",
    "/buscar?q={q}", "/sucursales?ciudad={ciudad}", "/promociones",
    "/catalogo?orden=precio&pagina={pag}", "/producto/ver?id={id}&color={color}",
]

_TERMINOS = ["nevera", "lavadora", "televisor", "licuadora", "microondas",
             "aire+acondicionado", "estufa", "audifonos", "portatil", "cafetera"]
_CIUDADES = ["bogota", "medellin", "cali", "barranquilla", "bucaramanga"]
_COLORES = ["negro", "blanco", "plata", "azul"]


def ruta_realista(rng: random.Random) -> str:
    """Rellena la plantilla de una ruta legítima con valores plausibles."""
    plantilla = rng.choice(WEB_PATHS_OK)
    return (plantilla
            .replace("{id}", str(rng.randint(1000, 9999)))
            .replace("{sku}", f"SKU-{rng.randint(10000, 99999)}")
            .replace("{suc}", str(rng.randint(1, 40)))
            .replace("{pag}", str(rng.randint(1, 12)))
            .replace("{q}", rng.choice(_TERMINOS))
            .replace("{ciudad}", rng.choice(_CIUDADES))
            .replace("{color}", rng.choice(_COLORES)))

MONTHS = ["Jan", "Feb", "Mar", "Apr", "May", "Jun",
          "Jul", "Aug", "Sep", "Oct", "Nov", "Dec"]


@dataclass
class Env:
    """Entorno del ejercicio. `variant` cambia la infraestructura del atacante."""

    variant: int = 0
    run_id: str = "run"

    attacker_ip: str = field(init=False)
    attacker_scan_ip: str = field(init=False)
    c2_ip: str = field(init=False)
    c2_domain: str = field(init=False)
    exfil_ip: str = field(init=False)
    webshell_name: str = field(init=False)
    implant_name: str = field(init=False)
    implant_sha256: str = field(init=False)
    victim_web: tuple = field(init=False)
    victim_file: tuple = field(init=False)
    compromised_svc: str = field(init=False)
    rng: random.Random = field(init=False)

    def __post_init__(self):
        self.rng = random.Random(1000 + self.variant)
        r = self.rng
        self.attacker_ip = f"45.155.{200 + self.variant % 40}.{r.randint(2, 250)}"
        self.attacker_scan_ip = f"91.240.{100 + self.variant % 50}.{r.randint(2, 250)}"
        self.c2_ip = f"185.243.{100 + self.variant % 50}.{r.randint(2, 250)}"
        self.exfil_ip = f"193.36.{10 + self.variant % 60}.{r.randint(2, 250)}"
        tag = "".join(r.choice(string.ascii_lowercase) for _ in range(7))
        self.c2_domain = f"cdn-{tag}.{r.choice(['top', 'xyz', 'click', 'live'])}"
        self.webshell_name = r.choice(
            ["estilos_v2.aspx", "img_upload.aspx", "sess_cache.aspx", "err404.aspx"]
        )
        self.implant_name = r.choice(
            ["svch0st.exe", "winlogen.exe", "updtsrv.exe", "msdtcx.exe"]
        )
        self.implant_sha256 = hashlib.sha256(
            f"{self.implant_name}:{self.variant}".encode()
        ).hexdigest()
        self.victim_web = SERVERS[0]
        self.victim_file = SERVERS[2]
        self.compromised_svc = "svc_backup"

    def iocs(self) -> dict:
        """IOCs de verdad de la campaña — se usan para el feed de TIM y el scoring."""
        return {
            "ips": [self.attacker_ip, self.attacker_scan_ip, self.c2_ip, self.exfil_ip],
            "domains": [self.c2_domain],
            "files": [self.implant_name, self.webshell_name],
            "hashes": [self.implant_sha256],
            "accounts": [self.compromised_svc],
            "hosts": [self.victim_web[0], self.victim_file[0]],
        }


# --------------------------------------------------------------------------
# Helpers de tiempo / formato
# --------------------------------------------------------------------------


def syslog_header(ts: datetime, host: str, tag: str) -> str:
    """Cabecera RFC3164:  'Aug  4 10:32:01 host tag:'  — sin año y sin zona,
    a propósito: es el dolor real de parsear syslog y da pie a la charla de
    'time standards' del deck de Log Source Best Practices."""
    m = MONTHS[ts.month - 1]
    return f"{m} {ts.day:2d} {ts:%H:%M:%S} {host} {tag}:"


def iso(ts: datetime) -> str:
    return ts.astimezone(timezone.utc).strftime("%Y-%m-%dT%H:%M:%S.%f")[:-3] + "Z"


def epoch_ms(ts: datetime) -> int:
    return int(ts.timestamp() * 1000)


def rand_hex(n: int, rng: random.Random) -> str:
    return "".join(rng.choice("0123456789abcdef") for _ in range(n))


def sha256_of(text: str) -> str:
    return hashlib.sha256(text.encode()).hexdigest()


# --------------------------------------------------------------------------
# WAF  →  syslog + CEF
# --------------------------------------------------------------------------


def waf_event(
    ts: datetime,
    src_ip: str,
    path: str,
    *,
    method: str = "GET",
    status: int = 200,
    action: str = "allow",          # allow | alert | block
    signature: str = "None",
    severity: int = 1,              # 0-10 en CEF
    user_agent: str | None = None,
    bytes_in: int = 0,
    bytes_out: int = 0,
    dst: str = "10.20.30.11",
    referer: str | None = None,
    payload: str = "",
    matched_param: str = "",
    account: str = "",
    session: str | None = None,
    host: str = "waf-dmz-01",
    rng: random.Random | None = None,
) -> str:
    rng = rng or random
    ua = user_agent or rng.choice(USER_AGENTS_OK)
    name = signature if signature != "None" else "HTTP Request"
    cat, attack_type, mitre = _threat_taxonomy(signature)

    # Contexto completo de la petición. Un WAF real captura el "href" de origen
    # y, cuando hay violación, el trozo exacto que la disparó — para que el
    # analista no tenga que ir a otro sistema a reconstruirla.
    ref = referer if referer is not None else _referer_para(path, rng, ua)
    sid = session or rand_hex(24, rng)
    if not payload and "?" in path:
        payload = path.split("?", 1)[1]
    if not matched_param and "=" in payload:
        matched_param = payload.split("=", 1)[0]

    # Una SQL injection ciega basada en tiempo TARDA lo que pide el payload.
    # Es la unica huella que deja: ni la firma ni el codigo de respuesta la
    # delatan, solo el reloj.
    demora = _demora_de(payload, rng)

    ctx = (
        f"dhost=tienda.{DOMAIN} "
        # suser = la cuenta que el WAF extrae del formulario o de la sesión.
        # Un "-" significa peticion anonima: nadie autenticado detras.
        f"suser={account or '-'} "
        f"requestContext={ref} "
        f"requestCookies=SESSIONID%3D{sid}%3Bcarrito%3D{rng.randint(0, 9)} "
        f"cn3Label=ResponseTimeMs cn3={demora} "
    )
    if payload:
        # URL-encoded a propósito: sin espacios, así el CEF sigue siendo
        # parseable y el analista ve el payload tal cual viajó.
        ctx += f"cs6Label=Payload cs6={payload[:400]} "
    if matched_param:
        ctx += f"flexString1Label=MatchedParam flexString1={matched_param} "

    ext = (
        f"rt={epoch_ms(ts)} cat={cat} src={src_ip} spt={rng.randint(1024, 65000)} "
        f"dst={dst} dpt=443 requestMethod={method} request=https://tienda.{DOMAIN}{path} "
        f"requestClientApplication={ua} act={action} "
        f"cs1Label=Policy cs1=WebApp-Prod cs2Label=Signature cs2={signature} "
        f"cs3Label=Country cs3={_country_for(src_ip)} "
        f"cs4Label=AttackType cs4={attack_type} "
        f"cs5Label=MitreTechnique cs5={mitre} "
        f"cn1Label=HTTPStatus cn1={status} cn2Label=ThreatSeverity cn2={severity} "
        f"in={bytes_in} out={bytes_out} "
        f"deviceDirection=0 outcome={'Blocked' if action == 'block' else 'Allowed'} "
        f"app=HTTPS deviceProcessName=waf-engine "
        + ctx.rstrip()
    )
    cef = f"CEF:0|Imperva|SecureSphere|14.7|{_sig_id(signature)}|{name}|{severity}|{ext}"
    return ts, f"{syslog_header(ts, host, 'CEF')} {cef}"


# Taxonomía por firma: categoría CEF, tipo de ataque y técnica MITRE.
# Es lo que permite que una regla de detección razone por CLASE de amenaza
# en vez de por el nombre exacto de la firma de un proveedor concreto.
_TAXONOMY = {
    "None":                   ("Application/Access", "Normal", "-"),
    "SQL Injection":          ("Application/Injection", "Injection", "T1190"),
    "Directory Traversal":    ("Application/PathTraversal", "PathTraversal", "T1083"),
    "Remote File Inclusion":  ("Application/Injection", "Injection", "T1190"),
    "Cross Site Scripting":   ("Application/XSS", "ClientSideInjection", "T1059.007"),
    "Malicious File Upload":  ("Application/Upload", "MaliciousUpload", "T1505.003"),
    "Web Scanner Detected":   ("Recon/Scanning", "Reconnaissance", "T1595.002"),
    "Protocol Anomaly":       ("Application/Protocol", "ProtocolViolation", "T1071.001"),
    "Bot Access Control":     ("Recon/Automation", "BotActivity", "T1595"),
    "Illegal Resource Access": ("Application/Access", "ForcefulBrowsing", "T1083"),
    "Credential Stuffing":    ("Identity/BruteForce", "BruteForce", "T1110.004"),
}


def _threat_taxonomy(signature: str):
    return _TAXONOMY.get(signature, ("Application/Other", "Unknown", "-"))


# De dónde venía el usuario. Para el tráfico legítimo suele ser una página
# interna o un buscador; una herramienta automatizada normalmente no manda
# Referer, y esa ausencia es en sí misma una señal.
_REFERERS_EXTERNOS = [
    "https://www.google.com/", "https://www.bing.com/",
    "https://l.facebook.com/", "https://t.co/", "https://www.instagram.com/",
]


_CLIENTES_AUTOMATIZADOS = ("python-requests", "curl/", "sqlmap", "Nmap", "Nikto",
                           "Go-http-client", "Scanning Engine", "Nessus", "wget")


_PATRONES_LENTOS = ("sleep", "waitfor", "pg_sleep", "benchmark", "dbms_pipe")


def _demora_de(payload: str, rng: random.Random) -> int:
    """Tiempo de respuesta en ms. Los payloads que piden una pausa la obtienen.

    Se decodifica primero: si no, el regex acaba leyendo los digitos del propio
    URL-encoding (%28 se convierte en "28 segundos") en vez del argumento real.
    """
    texto = urllib.parse.unquote_plus(payload).lower()
    if not any(t in texto for t in _PATRONES_LENTOS):
        return rng.randint(12, 850)

    segundos = 5
    m = re.search(r"delay\s*'?\s*\d{1,2}:\d{2}:(\d{1,2})", texto)      # WAITFOR DELAY '00:00:05'
    if not m:
        m = re.search(r"(?:sleep|pg_sleep)\s*\(\s*(\d{1,2})", texto)     # SLEEP(5)
    if not m:
        m = re.search(r"benchmark\s*\(\s*(\d+)", texto)                  # BENCHMARK(5000000,...)
        if m:
            return rng.randint(2000, 6000)
    if m:
        segundos = int(m.group(1))
    segundos = max(1, min(segundos, 30))
    return segundos * 1000 + rng.randint(5, 90)


def _referer_para(path: str, rng: random.Random, ua: str = "") -> str:
    # Una herramienta automatizada no encadena Referer. La ausencia de cabecera
    # en una petición con parámetros es una señal por sí sola.
    if any(t in ua for t in _CLIENTES_AUTOMATIZADOS):
        return "-"
    base = f"https://tienda.{DOMAIN}"
    if path in ("/", "/catalogo", "/promociones"):
        return rng.choice(_REFERERS_EXTERNOS) if rng.random() < 0.6 else "-"
    if path.startswith("/static/") or path.startswith("/api/"):
        return f"{base}/catalogo"
    return rng.choice([
        f"{base}/catalogo", f"{base}/buscar", f"{base}/", f"{base}/promociones",
        rng.choice(_REFERERS_EXTERNOS), "-",
    ])


_SIG_IDS = {
    "None": "0",
    "SQL Injection": "1001",
    "Directory Traversal": "1002",
    "Remote File Inclusion": "1003",
    "Cross Site Scripting": "1004",
    "Malicious File Upload": "1005",
    "Web Scanner Detected": "1006",
    "Protocol Anomaly": "1007",
    "Bot Access Control": "1008",
    "Illegal Resource Access": "1009",
    "Credential Stuffing": "1010",
}


def _sig_id(sig: str) -> str:
    return _SIG_IDS.get(sig, "1099")


def _country_for(ip: str) -> str:
    first = ip.split(".")[0]
    return {
        "45": "RU", "91": "NL", "185": "SC", "193": "RO",
        "10": "CO", "172": "CO", "192": "CO",
    }.get(first, "US")


# --------------------------------------------------------------------------
# Firewall  →  syslog + campos delimitados por pipe
# --------------------------------------------------------------------------

FW_FIELDS = (
    "type|subtype|time|src_ip|src_port|dst_ip|dst_port|proto|app|"
    "src_zone|dst_zone|action|bytes_sent|bytes_recv|packets|rule|src_host|session_id"
)


def fw_event(
    ts: datetime,
    src_ip: str,
    dst_ip: str,
    *,
    dst_port: int = 443,
    src_port: int | None = None,
    proto: str = "tcp",
    app: str = "ssl",
    action: str = "allow",          # allow | deny | drop
    bytes_sent: int = 0,
    bytes_recv: int = 0,
    src_zone: str = "trust",
    dst_zone: str = "untrust",
    rule: str = "salida-internet",
    src_host: str = "-",
    subtype: str = "end",
    host: str = "fw-perim-01",
    rng: random.Random | None = None,
) -> str:
    rng = rng or random
    src_port = src_port or rng.randint(49152, 65535)
    packets = max(1, (bytes_sent + bytes_recv) // 1400)
    body = "|".join(
        str(x)
        for x in [
            "TRAFFIC", subtype, iso(ts), src_ip, src_port, dst_ip, dst_port,
            proto, app, src_zone, dst_zone, action, bytes_sent, bytes_recv,
            packets, rule, src_host, rand_hex(8, rng),
        ]
    )
    return ts, f"{syslog_header(ts, host, 'ANDINA-NGFW')} {body}"


# Catálogo de firmas del motor de amenazas del NGFW (IPS / anti-spyware / UTM).
# Cada entrada: (threat_id, nombre, severidad, categoría)
FW_THREATS = {
    "port_scan":      (8002, "TCP Port Scan", "medium", "scan"),
    "host_sweep":     (8003, "Host Sweep", "medium", "scan"),
    "ssh_brute":      (40004, "SSH User Authentication Brute Force Attempt",
                       "high", "brute-force"),
    "smb_brute":      (40015, "SMB User Authentication Brute Force Attempt",
                       "high", "brute-force"),
    "rdp_brute":      (40021, "RDP User Authentication Brute Force Attempt",
                       "high", "brute-force"),
    "sqli_net":       (31682, "SQL Injection Attempt Detected", "high", "code-execution"),
    "webshell":       (86123, "Web Shell Activity Detected", "critical", "code-execution"),
    "smb_exploit":    (36729, "Microsoft Windows SMB Remote Code Execution",
                       "critical", "code-execution"),
    "c2_generic":     (13245, "Generic Command and Control Traffic", "critical", "botnet"),
    "c2_dga":         (14588, "Suspicious DNS Query (Generic DGA Domain)",
                       "high", "dns-c2"),
    "malware_dl":     (25901, "Malicious Executable Download", "critical", "file"),
    "url_malware":    (99001, "URL Filtering: categoría malware", "high", "url"),
    "data_exfil":     (54277, "Large Outbound Data Transfer to Rare Destination",
                       "medium", "data-loss"),
}


def fw_threat_event(
    ts: datetime,
    src_ip: str,
    dst_ip: str,
    threat_key: str,
    *,
    dst_port: int = 443,
    src_port: int | None = None,
    proto: str = "tcp",
    app: str = "unknown",
    action: str = "alert",            # alert | block | reset-both | drop
    subtype: str | None = None,       # vulnerability | spyware | scan | url | file
    src_zone: str = "untrust",
    dst_zone: str = "dmz",
    rule: str = "proteccion-perimetro",
    repeat: int = 1,
    direction: str = "client-to-server",
    bytes_sent: int = 0,
    bytes_recv: int = 0,
    src_host: str = "-",
    extra: str = "",
    host: str = "fw-perim-01",
    rng: random.Random | None = None,
) -> tuple:
    """Log de amenaza del NGFW: IPS, anti-spyware, filtrado de URL, antivirus.

    Mantiene los mismos 18 campos que el log de TRAFFIC, pero el campo 16 lleva
    el detalle de la amenaza como pares clave=valor separados por ';'. Es
    exactamente el dolor que provoca un NGFW real: un mismo flujo de syslog
    donde el significado de un campo depende del subtipo.
    """
    rng = rng or random
    tid, tname, tsev, tcat = FW_THREATS[threat_key]
    subtype = subtype or _subtype_for(tcat)
    src_port = src_port or rng.randint(49152, 65535)
    detalle = (
        f"threat_id={tid};threat_name={tname};severity={tsev};category={tcat};"
        f"direction={direction};repeat={repeat};src_host={src_host}"
    )
    if extra:
        detalle += f";{extra}"
    body = "|".join(
        str(x)
        for x in [
            "THREAT", subtype, iso(ts), src_ip, src_port, dst_ip, dst_port,
            proto, app, src_zone, dst_zone, action, bytes_sent, bytes_recv,
            max(1, repeat), rule, detalle, rand_hex(8, rng),
        ]
    )
    return ts, f"{syslog_header(ts, host, 'ANDINA-NGFW')} {body}"


def _subtype_for(categoria: str) -> str:
    return {
        "scan": "scan",
        "brute-force": "vulnerability",
        "code-execution": "vulnerability",
        "botnet": "spyware",
        "dns-c2": "spyware",
        "file": "file",
        "url": "url",
        "data-loss": "data",
    }.get(categoria, "vulnerability")


def fw_dns_event(
    ts: datetime, src_ip: str, query: str, answer: str = "-",
    *, action: str = "allow", category: str = "computer-and-internet-info",
    src_zone: str = "trust", host: str = "fw-perim-01",
    rng: random.Random | None = None,
) -> str:
    """Log de DNS/URL filtering — mismo colector, subtipo distinto.
    Enseña que un dataset puede traer varios tipos de evento y que el
    modeling rule necesita filtros condicionales."""
    rng = rng or random
    body = "|".join(
        str(x)
        for x in [
            "THREAT", "dns", iso(ts), src_ip, rng.randint(49152, 65535),
            "10.20.40.5", 53, "udp", "dns", src_zone, "untrust", action,
            len(query) + 28, len(answer) + 40, 2, "dns-outbound",
            f"query={query};answer={answer};category={category}",
            rand_hex(8, rng),
        ]
    )
    return ts, f"{syslog_header(ts, host, 'ANDINA-NGFW')} {body}"


# --------------------------------------------------------------------------
# EDR  →  JSON anidado
# --------------------------------------------------------------------------

SIGNED_MS = ("Microsoft Corporation", True)
UNSIGNED = ("", False)


def edr_process_event(
    ts: datetime,
    hostname: str,
    host_ip: str,
    *,
    proc_name: str,
    proc_path: str,
    cmdline: str,
    user: str,
    parent_name: str = "explorer.exe",
    parent_path: str = "C:\\Windows\\explorer.exe",
    parent_cmdline: str = "C:\\Windows\\explorer.exe",
    ancestry: list[str] | None = None,
    signer: str = "Microsoft Corporation",
    signed: bool = True,
    integrity: str = "medium",
    sha256: str | None = None,
    detection: dict | None = None,
    rng: random.Random | None = None,
) -> str:
    rng = rng or random
    ev = {
        "ts": iso(ts),
        "ingest_ts": iso(ts + timedelta(seconds=rng.randint(1, 4))),
        "sensor": {
            "id": sha256_of(hostname)[:16],
            "hostname": hostname,
            "ip": host_ip,
            "os": "windows",
            "os_version": "10.0.20348",
            "agent_version": "8.4.1",
        },
        "event": {
            "id": rand_hex(16, rng),
            "category": "process",
            "type": "process",
            "action": "start",
        },
        "process": {
            "pid": rng.randint(1000, 9999),
            "name": proc_name,
            "path": proc_path,
            "cmdline": cmdline,
            "sha256": sha256 or sha256_of(proc_path),
            "md5": sha256_of(proc_path)[:32],
            "signed": signed,
            "signer": signer,
            "integrity_level": integrity,
            "user": user,
        },
        "parent": {
            "pid": rng.randint(500, 999),
            "name": parent_name,
            "path": parent_path,
            "cmdline": parent_cmdline,
        },
        "ancestry": ancestry or [parent_name, proc_name],
    }
    if detection:
        ev["detection"] = detection
    return ts, json.dumps(ev, ensure_ascii=False)


def edr_file_event(
    ts: datetime, hostname: str, host_ip: str, *,
    action: str, file_path: str, file_name: str, proc_name: str, user: str,
    sha256: str | None = None, size: int = 0,
    detection: dict | None = None, rng: random.Random | None = None,
) -> str:
    rng = rng or random
    ev = {
        "ts": iso(ts),
        "sensor": {"id": sha256_of(hostname)[:16], "hostname": hostname,
                   "ip": host_ip, "os": "windows"},
        "event": {"id": rand_hex(16, rng), "category": "file",
                  "type": "file", "action": action},
        "file": {
            "path": file_path, "name": file_name, "size": size,
            "sha256": sha256 or sha256_of(file_path),
            "extension": file_name.rsplit(".", 1)[-1] if "." in file_name else "",
        },
        "process": {"name": proc_name, "pid": rng.randint(1000, 9999), "user": user},
    }
    if detection:
        ev["detection"] = detection
    return ts, json.dumps(ev, ensure_ascii=False)


def edr_network_event(
    ts: datetime, hostname: str, host_ip: str, *,
    proc_name: str, proc_path: str, remote_ip: str, remote_port: int,
    direction: str = "outbound", bytes_sent: int = 0, bytes_recv: int = 0,
    user: str = "SYSTEM", domain: str = "", rng: random.Random | None = None,
) -> str:
    rng = rng or random
    ev = {
        "ts": iso(ts),
        "sensor": {"id": sha256_of(hostname)[:16], "hostname": hostname,
                   "ip": host_ip, "os": "windows"},
        "event": {"id": rand_hex(16, rng), "category": "network",
                  "type": "network", "action": "connection"},
        "network": {
            "direction": direction, "protocol": "tcp",
            "local_ip": host_ip, "local_port": rng.randint(49152, 65535),
            "remote_ip": remote_ip, "remote_port": remote_port,
            "remote_domain": domain,
            "bytes_sent": bytes_sent, "bytes_received": bytes_recv,
        },
        "process": {"name": proc_name, "path": proc_path,
                    "pid": rng.randint(1000, 9999), "user": user},
    }
    return ts, json.dumps(ev, ensure_ascii=False)


def edr_registry_event(
    ts: datetime, hostname: str, host_ip: str, *,
    key: str, value_name: str, value_data: str, proc_name: str,
    proc_path: str, user: str, action: str = "set_value",
    detection: dict | None = None, rng: random.Random | None = None,
) -> str:
    rng = rng or random
    ev = {
        "ts": iso(ts),
        "sensor": {"id": sha256_of(hostname)[:16], "hostname": hostname,
                   "ip": host_ip, "os": "windows"},
        "event": {"id": rand_hex(16, rng), "category": "registry",
                  "type": "registry", "action": action},
        "registry": {"key": key, "value_name": value_name, "value_data": value_data},
        "process": {"name": proc_name, "path": proc_path,
                    "pid": rng.randint(1000, 9999), "user": user},
    }
    if detection:
        ev["detection"] = detection
    return ts, json.dumps(ev, ensure_ascii=False)


def edr_prevention_event(
    ts: datetime,
    hostname: str,
    host_ip: str,
    *,
    action: str,                    # quarantine | terminate | block | remediate | allow_by_exception
    rule_name: str,
    verdict: str = "malicious",     # malicious | suspicious | pup | benign | unknown
    proc_name: str = "",
    proc_path: str = "",
    cmdline: str = "",
    file_path: str = "",
    sha256: str = "",
    user: str = "",
    mitre: list[str] | None = None,
    severity: str = "high",
    exception_name: str = "",       # solo si action = allow_by_exception
    exception_scope: str = "",
    engine: str = "behavioral",     # behavioral | signature | ml | memory | script
    rng: random.Random | None = None,
) -> tuple:
    """Evento de PREVENCIÓN del agente: lo que el EDR bloqueó, puso en cuarentena,
    terminó… o dejó pasar porque una exclusión se lo impidió.

    Ese último caso (`allow_by_exception`) es el más valioso del laboratorio: una
    exclusión mal delimitada es la forma más común de que un EDR bien configurado
    no detenga un ataque, y casi nadie la busca en los logs."""
    rng = rng or random
    ev = {
        "ts": iso(ts),
        "sensor": {
            "id": sha256_of(hostname)[:16],
            "hostname": hostname,
            "ip": host_ip,
            "os": "windows",
            "agent_version": "8.4.1",
        },
        "event": {
            "id": rand_hex(16, rng),
            "category": "prevention",
            "type": "prevention",
            "action": action,
        },
        "prevention": {
            "rule_name": rule_name,
            "engine": engine,
            "verdict": verdict,
            "severity": severity,
            "blocked": action in ("quarantine", "terminate", "block", "remediate"),
        },
        "process": {
            "name": proc_name,
            "path": proc_path,
            "cmdline": cmdline,
            "pid": rng.randint(1000, 9999),
            "user": user,
        },
        "file": {"path": file_path, "sha256": sha256} if file_path else {},
        "detection": {
            "severity": severity,
            "name": rule_name,
            "mitre": mitre or [],
        },
    }
    if action == "allow_by_exception":
        ev["prevention"]["exception"] = {
            "name": exception_name,
            "scope": exception_scope,
            "matched": True,
        }
    return ts, json.dumps(ev, ensure_ascii=False)


def edr_agent_event(
    ts: datetime,
    hostname: str,
    host_ip: str,
    *,
    action: str,                    # tamper_attempt | service_stopped | protection_disabled
                                    # | agent_offline | policy_changed | scan_completed
    detail: str = "",
    proc_name: str = "",
    proc_path: str = "",
    cmdline: str = "",
    user: str = "",
    outcome: str = "blocked",       # blocked | succeeded
    severity: str = "high",
    rng: random.Random | None = None,
) -> tuple:
    """Salud e integridad del propio agente. Un atacante que intenta apagar el EDR
    es una de las señales de mayor fidelidad que existen — y una de las que más se
    pasan por alto, porque no está en el dataset de procesos."""
    rng = rng or random
    ev = {
        "ts": iso(ts),
        "sensor": {
            "id": sha256_of(hostname)[:16],
            "hostname": hostname,
            "ip": host_ip,
            "os": "windows",
            "agent_version": "8.4.1",
        },
        "event": {
            "id": rand_hex(16, rng),
            "category": "agent",
            "type": "agent_health",
            "action": action,
            "outcome": outcome,
        },
        "agent": {
            "detail": detail,
            "tamper_protection": "enabled",
            "severity": severity,
        },
        "process": {
            "name": proc_name, "path": proc_path,
            "cmdline": cmdline, "user": user,
            "pid": rng.randint(1000, 9999),
        },
    }
    return ts, json.dumps(ev, ensure_ascii=False)


# --------------------------------------------------------------------------
# Autenticación  →  JSON
# --------------------------------------------------------------------------


def auth_event(
    ts: datetime,
    user: str,
    *,
    outcome: str = "success",       # success | failure
    reason: str = "",
    src_ip: str = "10.20.10.14",
    src_host: str = "-",
    dst_ip: str = "10.20.40.5",
    dst_host: str = "SRV-DC-01",
    logon_type: int = 3,
    protocol: str = "kerberos",
    mfa: bool = True,
    app: str = "windows-logon",
    rng: random.Random | None = None,
) -> str:
    rng = rng or random
    ev = {
        "time": iso(ts),
        "event": {
            "id": rand_hex(16, rng),
            "category": "authentication",
            "action": "logon",
            "outcome": outcome,
            "reason": reason,
            "code": 4624 if outcome == "success" else 4625,
        },
        "user": {
            "name": user,
            "domain": ORG,
            "upn": f"{user}@{DOMAIN}",
            "privileged": user in ("administrador", "adminti", "svc_backup"),
        },
        "src": {
            "ip": src_ip,
            "host": src_host,
            "port": rng.randint(49152, 65535),
            "country": _country_for(src_ip),
        },
        "dst": {"ip": dst_ip, "host": dst_host, "port": 445 if logon_type == 3 else 3389},
        "auth": {"protocol": protocol, "logon_type": logon_type,
                 "package": protocol.upper(), "application": app},
        "mfa": {"used": mfa, "method": "push" if mfa else ""},
    }
    return ts, json.dumps(ev, ensure_ascii=False)
