#!/usr/bin/env python3
"""
run_lab.py — Consola del laboratorio XSIAM Deep Dive.

Comandos:

  check      Prueba de conectividad: manda un evento canario a cada colector.
  baseline   Genera tráfico normal del negocio (+ falsos positivos plantados).
  attack     Reproduce la campaña "OPERACIÓN CASCABEL" completa o por fases.
  iocs       Exporta los IOCs de la campaña en CSV/JSON (para el feed de TIM).
  info       Muestra el entorno de una variante (para la guía del instructor).

Ejemplos:

  # 0. ¿Llegan los eventos?
  python run_lab.py check

  # 1. Día 2: 48 h de línea base, con marca de tiempo hacia atrás, lo más rápido posible
  python run_lab.py baseline --hours 48 --eps-scale 0.4

  # 2. Día 3-4: ataque con marcas de tiempo en el pasado (para escribir detecciones)
  python run_lab.py attack --variant 1 --backfill-hours 6

  # 3. Día 5 capstone: ataque EN VIVO, comprimido 20x, variante por equipo
  python run_lab.py attack --variant 3 --live --speed 20 --with-impact

  # 4. Solo una fase (útil para demos en clase)
  python run_lab.py attack --phases execution,c2 --live --speed 10

  # 5. Ver qué se enviaría sin tocar el tenant
  python run_lab.py attack --dry-run

  # --- Modo instructor con varios equipos (sección "teams" en config.json) ---

  python run_lab.py --all-teams check                  # ¿todos los tenants reciben?
  python run_lab.py --team equipo_azul baseline --hours 48

  # Día 3 — ataque de entrenamiento (variantes 1, 2, 3…)
  python run_lab.py --all-teams --quiet-progress attack --backfill-hours 6

  # Día 5 — capstone con OTROS IOCs (variantes 11, 12, 13…)
  python run_lab.py --all-teams --variant-shift 10 --quiet-progress \
                    attack --live --speed 10 --with-impact
"""

from __future__ import annotations

import argparse
import csv
import json
import os
import sys
import threading
import time
from datetime import datetime, timedelta, timezone

from baseline import generate_baseline
from generators import Env
from xsiam_client import (HTTP_BACKEND, CollectorSet, list_teams, load_config,
                          resolve_team_config)

# `scenario.py` solo está en el paquete del instructor. Se importa de forma
# perezosa para que el paquete del alumno (sin ese archivo) funcione igual
# para `check`, `baseline` e `info`.
try:
    from scenario import Campaign
except ImportError:                                   # pragma: no cover
    Campaign = None

SOURCES = ("waf", "fw", "edr", "auth")

# Con --all-teams cada equipo corre en su propio hilo; sin esto los informes
# de los 3 equipos se entrelazan y no se entiende nada en pantalla.
_PRINT_LOCK = threading.Lock()


def say(msg: str, label: str | None = None) -> None:
    with _PRINT_LOCK:
        if label:
            msg = "\n".join(f"[{label}] {ln}" for ln in msg.splitlines())
        print(msg, file=sys.stderr)

NO_SCENARIO_MSG = """
Este paquete no incluye 'scenario.py', así que no puede lanzar la campaña.

Es intencional: el escenario de ataque lo controla el instructor, para que la
campaña del capstone sea una sorpresa. Tú sí puedes usar 'check', 'baseline'
e 'info' para alimentar tu tenant con tráfico normal.
"""


def _team_context(args, team: str | None):
    """Devuelve (cfg_del_equipo, variante_efectiva, etiqueta)."""
    cfg = load_config(args.config)
    tcfg = resolve_team_config(cfg, team)
    variant = args.variant
    if team and tcfg.get("_variant") is not None and args.variant == 0:
        variant = tcfg["_variant"]           # la variante del equipo, si no se forzó otra
    # --variant-shift permite correr la MISMA topología de equipos con otro juego de
    # IOCs. Es lo que separa el ataque de entrenamiento del Día 3 del capstone del
    # Día 5: mismo comportamiento, IPs y hashes distintos.
    variant += getattr(args, "variant_shift", 0)
    label = team or args.run_id
    return tcfg, variant, label


# --------------------------------------------------------------------------
# Motor de envío
# --------------------------------------------------------------------------


def _merge(streams: dict) -> list[tuple]:
    """Une los 4 flujos en una sola línea de tiempo: [(ts, source, linea), ...]"""
    merged = []
    for src, evs in streams.items():
        for ts, line in evs:
            merged.append((ts, src, line))
    merged.sort(key=lambda x: x[0])
    return merged


def deliver(streams: dict, cs: CollectorSet, *, live: bool = False,
            speed: float = 1.0, verbose: bool = True) -> None:
    """Envía los eventos. En modo `live` respeta los intervalos reales
    divididos por `speed` (speed=60 → 1 hora simulada = 1 minuto real)."""
    merged = _merge(streams)
    if not merged:
        print("No hay eventos que enviar.", file=sys.stderr)
        return

    total = len(merged)
    t_start = merged[0][0]
    wall_start = time.monotonic()
    last_report = 0

    for i, (ts, src, line) in enumerate(merged, 1):
        if live:
            target = (ts - t_start).total_seconds() / max(speed, 0.001)
            drift = target - (time.monotonic() - wall_start)
            if drift > 0:
                time.sleep(min(drift, 5.0))
        cs.send(src, [line])

        if verbose and (i - last_report >= 2000 or i == total):
            last_report = i
            pct = 100.0 * i / total
            sim = (ts - t_start).total_seconds() / 60.0
            print(f"\r  enviando… {i:,}/{total:,} ({pct:5.1f}%)  "
                  f"t+{sim:6.0f} min simulados", end="", file=sys.stderr)
    if verbose:
        print(file=sys.stderr)
    cs.flush()


# --------------------------------------------------------------------------
# Comandos
# --------------------------------------------------------------------------


def cmd_check(args) -> int:
    targets = _targets(args)
    all_ok = True
    for team in targets:
        if team:
            print(f"\n===== {team} =====", file=sys.stderr)
        tcfg, _v, _l = _team_context(args, team)
        ok = _check_one(args, tcfg)
        all_ok = all_ok and ok
    return 0 if all_ok else 1


def _check_one(args, cfg) -> bool:
    print(f"  motor HTTP: {HTTP_BACKEND}", file=sys.stderr)
    cs = CollectorSet(cfg, dry_run=args.dry_run, only=args.sources)
    if not cs.collectors:
        print("Ningún colector configurado. Copia config.example.json a config.json "
              "y pon las API keys.", file=sys.stderr)
        return False
    ok = all(c.test() for c in cs.collectors.values())
    print(cs.report())
    if ok:
        print("\nTodo OK. En XSIAM: Data Management → Data Sources debería aparecer "
              "actividad, y en el Query Builder:\n"
              "  dataset = <tu_dataset> | filter lab = \"xsiam-deep-dive\" | limit 10")
    cs.close()
    return ok


def cmd_baseline(args) -> int:
    targets = _targets(args)
    for team in targets:
        if team:
            print(f"\n===== {team} =====", file=sys.stderr)
        tcfg, variant, label = _team_context(args, team)
        _baseline_one(args, tcfg, variant, label)
    return 0


def _baseline_one(args, cfg, variant: int, label: str) -> int:
    env = Env(variant=variant, run_id=label)

    end = datetime.now(timezone.utc) if not args.end else _parse_dt(args.end)
    start = end - timedelta(hours=args.hours)
    print(f"Generando {args.hours} h de línea base "
          f"({start:%Y-%m-%d %H:%M} → {end:%Y-%m-%d %H:%M} UTC)…", file=sys.stderr)

    streams = generate_baseline(env, start, args.hours, eps_scale=args.eps_scale)
    counts = {k: len(v) for k, v in streams.items()}
    print(f"  eventos generados: {counts}  total={sum(counts.values()):,}", file=sys.stderr)

    cs = CollectorSet(cfg, dry_run=args.dry_run,
                      dry_run_dir=os.path.join(args.out, label), only=args.sources)
    deliver(streams, cs, live=False)
    print(cs.report())
    cs.close()
    return 0


def cmd_attack(args) -> int:
    if Campaign is None:
        print(NO_SCENARIO_MSG, file=sys.stderr)
        return 3
    targets = _targets(args)

    if len(targets) > 1:
        # Capstone multi-equipo: hay que atacar a todos A LA VEZ, no en fila.
        import threading
        hilos = []
        for team in targets:
            tcfg, variant, label = _team_context(args, team)
            t = threading.Thread(target=_attack_one, args=(args, tcfg, variant, label),
                                 name=label, daemon=False)
            hilos.append(t)
        print(f"Lanzando la campaña contra {len(hilos)} equipos en paralelo…\n",
              file=sys.stderr)
        for t in hilos:
            t.start()
        for t in hilos:
            t.join()
        print("\nTodos los equipos han recibido la campaña completa.", file=sys.stderr)
        return 0

    tcfg, variant, label = _team_context(args, targets[0])
    return _attack_one(args, tcfg, variant, label)


def _attack_one(args, cfg, variant: int, label: str) -> int:
    env = Env(variant=variant, run_id=label)

    if args.live:
        t0 = datetime.now(timezone.utc)
    else:
        t0 = datetime.now(timezone.utc) - timedelta(hours=args.backfill_hours)

    phases = None
    if args.phases and args.phases != "all":
        phases = [p.strip() for p in args.phases.split(",")]
    elif args.phases == "all" or args.with_impact:
        phases = list(Campaign.PHASES)
        if not args.with_impact:
            phases.remove("impact")

    camp = Campaign(env, t0)
    streams, truth = camp.build(phases=phases, c2_minutes=args.c2_minutes)
    counts = {k: len(v) for k, v in streams.items()}
    say(f"OPERACIÓN CASCABEL — variante {env.variant} — t0={t0:%Y-%m-%d %H:%M UTC}\n"
        f"  eventos: {counts}  total={sum(counts.values()):,}", label)

    # Ground truth: la referencia objetiva para calcular MTTD y cobertura
    os.makedirs(args.out, exist_ok=True)
    gt_path = os.path.join(args.out, f"ground_truth_{env.run_id}_v{env.variant}.json")
    with open(gt_path, "w", encoding="utf-8") as fh:
        json.dump(camp.ground_truth(), fh, indent=2, ensure_ascii=False)
    say(f"  ground truth → {gt_path}  (NO compartir hasta el debrief)", label)

    if args.live:
        dur = (max(t[0] for t in _merge(streams)) - t0).total_seconds() / 60
        say(f"  modo EN VIVO: {dur:.0f} min simulados / {args.speed}x = "
            f"~{dur/args.speed:.1f} min reales", label)

    cs = CollectorSet(cfg, dry_run=args.dry_run,
                      dry_run_dir=os.path.join(args.out, label), only=args.sources)
    deliver(streams, cs, live=args.live, speed=args.speed,
            verbose=(not args.quiet_progress))
    say(cs.report(), label)
    cs.close()
    return 0


def cmd_iocs(args) -> int:
    for team in _targets(args):
        _c, variant, label = _team_context(args, team)
        _iocs_one(args, variant, label)
    return 0


def _iocs_one(args, variant: int, label: str) -> int:
    env = Env(variant=variant, run_id=label)
    iocs = env.iocs()
    os.makedirs(args.out, exist_ok=True)

    rows = []
    for ip in iocs["ips"]:
        rows.append(("IP", ip, "OPERACION-CASCABEL", "C" if ip == env.c2_ip else "B", 3))
    for d in iocs["domains"]:
        rows.append(("Domain", d, "OPERACION-CASCABEL", "B", 3))
    for h in iocs["hashes"]:
        rows.append(("File", h, "OPERACION-CASCABEL", "B", 3))

    csv_path = os.path.join(args.out, f"iocs_cascabel_v{env.variant}.csv")
    with open(csv_path, "w", newline="", encoding="utf-8") as fh:
        w = csv.writer(fh)
        w.writerow(["indicator_type", "value", "campaign", "reliability", "score"])
        w.writerows(rows)

    json_path = os.path.join(args.out, f"iocs_cascabel_v{env.variant}.json")
    with open(json_path, "w", encoding="utf-8") as fh:
        json.dump(iocs, fh, indent=2, ensure_ascii=False)

    print(f"CSV para subir a TIM → {csv_path}")
    print(f"JSON → {json_path}")
    print(json.dumps(iocs, indent=2, ensure_ascii=False))
    return 0


def cmd_info(args) -> int:
    for team in _targets(args):
        _c, variant, label = _team_context(args, team)
        if team:
            print(f"\n===== {team} =====")
        _info_one(variant, label)
    return 0


def _info_one(variant: int, label: str) -> int:
    env = Env(variant=variant, run_id=label)
    print(json.dumps({
        "equipo": label,
        "variant": env.variant,
        "attacker_ip": env.attacker_ip,
        "scanner_ip": env.attacker_scan_ip,
        "c2_ip": env.c2_ip,
        "c2_domain": env.c2_domain,
        "exfil_ip": env.exfil_ip,
        "webshell": env.webshell_name,
        "implant": env.implant_name,
        "implant_sha256": env.implant_sha256,
        "victim_web": env.victim_web,
        "victim_file": env.victim_file,
        "compromised_account": env.compromised_svc,
    }, indent=2, ensure_ascii=False))
    return 0


def _targets(args) -> list:
    """Lista de equipos a procesar. [None] = modo individual (config de nivel superior)."""
    if getattr(args, "all_teams", False):
        cfg = load_config(args.config)
        teams = list_teams(cfg)
        if not teams:
            print("--all-teams pero la config no tiene sección 'teams'.", file=sys.stderr)
            sys.exit(2)
        return teams
    return [getattr(args, "team", None)]


def _parse_dt(s: str) -> datetime:
    return datetime.fromisoformat(s).replace(tzinfo=timezone.utc)


# --------------------------------------------------------------------------


def main(argv=None) -> int:
    p = argparse.ArgumentParser(
        prog="run_lab.py",
        description="Simulador de fuentes de log para el laboratorio Cortex XSIAM Deep Dive",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=__doc__,
    )
    p.add_argument("--config", default=None, help="ruta a config.json")
    p.add_argument("--variant", type=int, default=0,
                   help="variante del escenario (una por equipo: cambia IPs, dominio C2, malware)")
    p.add_argument("--run-id", default="lab", help="etiqueta de esta corrida")
    p.add_argument("--out", default="out", help="carpeta de salida (ground truth, dry-run, IOCs)")
    p.add_argument("--dry-run", action="store_true",
                   help="no envía nada: escribe los eventos en --out/<fuente>.log")
    p.add_argument("--sources", nargs="*", choices=SOURCES, default=None,
                   help="limitar a ciertas fuentes")
    p.add_argument("--team", default=None,
                   help="usa los colectores de un equipo de la sección 'teams' de la config")
    p.add_argument("--all-teams", action="store_true",
                   help="aplica a TODOS los equipos de la config "
                        "(el ataque se lanza en paralelo, que es lo que quieres en el capstone)")
    p.add_argument("--variant-shift", type=int, default=0,
                   help="suma N a la variante de cada equipo. Úsalo para que el ataque "
                        "de entrenamiento (Día 3) y el capstone (Día 5) tengan IOCs "
                        "distintos: el mismo comportamiento con otras IPs y otros hashes")
    p.add_argument("--quiet-progress", action="store_true",
                   help="sin barra de progreso (recomendado con --all-teams)")

    sub = p.add_subparsers(dest="cmd", required=True)

    sp = sub.add_parser("check", help="prueba de conectividad de los colectores")
    sp.set_defaults(func=cmd_check)

    sp = sub.add_parser("baseline", help="tráfico normal + falsos positivos")
    sp.add_argument("--hours", type=int, default=48)
    sp.add_argument("--eps-scale", type=float, default=1.0,
                    help="multiplicador de volumen (0.3 = tenant pequeño)")
    sp.add_argument("--end", default=None,
                    help="fin de la ventana, ISO UTC (por defecto: ahora)")
    sp.set_defaults(func=cmd_baseline)

    sp = sub.add_parser("attack", help="campaña OPERACIÓN CASCABEL")
    sp.add_argument("--phases", default=None,
                    help="all | recon,initial,execution,c2,credentials,lateral,exfil,impact")
    sp.add_argument("--with-impact", action="store_true",
                    help="incluye la fase de ransomware (F8)")
    sp.add_argument("--c2-minutes", type=int, default=180,
                    help="duración del beaconing en minutos simulados")
    sp.add_argument("--live", action="store_true",
                    help="reproduce en tiempo real (para el capstone)")
    sp.add_argument("--speed", type=float, default=20.0,
                    help="factor de compresión temporal en modo --live")
    sp.add_argument("--backfill-hours", type=float, default=4.0,
                    help="en modo no-live, cuántas horas atrás empieza el ataque")
    sp.set_defaults(func=cmd_attack)

    sp = sub.add_parser("iocs", help="exporta los IOCs de la campaña")
    sp.set_defaults(func=cmd_iocs)

    sp = sub.add_parser("info", help="muestra el entorno de una variante")
    sp.set_defaults(func=cmd_info)

    args = p.parse_args(argv)
    return args.func(args)


if __name__ == "__main__":
    sys.exit(main())
