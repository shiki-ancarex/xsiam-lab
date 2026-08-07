r"""
baseline.py — Tráfico "normal" del negocio + actividad legítima ruidosa.

Dos objetivos pedagógicos:

1. Que las detecciones no sean triviales. Si el único evento del tenant es el
   ataque, cualquier query lo encuentra. Con ruido, el alumno tiene que escribir
   filtros de verdad.

2. Generar falsos positivos *reales* y recurrentes, para que en el Día 4 tengan
   que aplicar el patrón de exclusiones (allowlisting) en vez de aflojar la
   detección:

   FP-1  Escáner de vulnerabilidades interno (los martes) golpea el WAF con
         firmas de SQLi/XSS desde 10.20.12.50 → parece el recon del atacante.
   FP-2  SCCM/despliegue de software lanza `powershell.exe -enc <base64>` en
         estaciones, firmado por Microsoft, desde ccmexec.exe → parece la
         ejecución del atacante.
   FP-3  Job de respaldo nocturno usa 7z.exe sobre \\SRV-FILE-01\clientes y
         sube ~2 GB a un destino en la nube → parece la exfiltración.
   FP-4  Monitoreo (Zabbix) hace beaconing cada 60 s a un colector externo
         → parece C2.
   FP-5  Ráfagas de logon fallido de `svc_sql` por una contraseña vencida
         → parece password spraying.
   FP-6  El mismo escáner Nessus barre la red interna los martes: dispara firmas
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
    BENIGN_DST, ORG, SERVERS, USERS, WEB_PATHS_OK, WORKSTATIONS, Env,
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
            path = rng.choice(WEB_PATHS_OK)
            status = rng.choices([200, 200, 200, 302, 304, 404, 500],
                                 weights=[70, 10, 5, 6, 4, 4, 1])[0]
            out["waf"].append(waf_event(
                ts, _public_ip(rng), path,
                method=rng.choices(["GET", "POST"], weights=[85, 15])[0],
                status=status, action="allow",
                bytes_in=rng.randint(300, 2500), bytes_out=rng.randint(500, 90000),
                rng=rng,
            ))

        # Bots y escaneos de fondo de Internet: ruido de baja severidad
        for _ in range(int(25 * w)):
            ts = hour_start + timedelta(seconds=rng.randint(0, 3599))
            out["waf"].append(waf_event(
                ts, _public_ip(rng),
                rng.choice(["/wp-login.php", "/.env", "/admin", "/phpmyadmin/"]),
                status=404, action="block", signature="Illegal Resource Access",
                severity=3, rng=rng,
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

    # FP-1 — escáner de vulnerabilidades interno, martes 02:00-04:00
    if dow == 1 and 2 <= h < 4:
        for _ in range(180):
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
    if dow == 1 and 2 <= h < 4:
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
