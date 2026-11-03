"""Orchestrates enumerations, checkpoint recovery and clean CLI failures."""
from __future__ import annotations

import argparse
import asyncio
import dataclasses
import hashlib
import json
import sys
from pathlib import Path

from .config import Config, load_config, validate_ports, validate_target
from .scanner_nmap import discover, fingerprint, open_tcp_ports
from .scanner_web import scan_web, web_services
from .vuln_lookup import lookup
from .report import write_report
from .utils import atomic_json, load_json, phase_checkpoint, utc_now, exists


def parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(description="Enumerazione iniziale CTF/lab autorizzati (nessuna exploitation).")
    p.add_argument("target", help="IP o hostname del lab")
    p.add_argument("--ports", help="Porte TCP custom, per esempio 22,80,8000-9000 (default: tutte)")
    p.add_argument("--wordlist", type=Path, help="Override del percorso wordlist Gobuster")
    p.add_argument("--config", type=Path, default=Path(__file__).resolve().parent.parent / "config.toml")
    p.add_argument("--output", type=Path, help="Cartella report (default: ./reports/<target>)")
    p.add_argument("--min-rate", type=int, help="Override Nmap --min-rate")
    p.add_argument("--threads", type=int, help="Override Gobuster -t")
    p.add_argument("--nvd", action="store_true", help="Abilita lookup online NVD (rate-limit applicato)")
    p.add_argument("--resume", action="store_true", help="Riusa i checkpoint completati con lo stesso scope/config")
    p.add_argument("--skip-web", action="store_true", help="Salta Gobuster e Webanalyze")
    p.add_argument("--authorized", action="store_true", help="Conferma di disporre dell'autorizzazione del target")
    return p


def key_for(target: str, ports: str, cfg: Config, nvd: bool, skip_web: bool) -> str:
    relevant = {**dataclasses.asdict(cfg), "target": target, "ports": ports, "nvd": nvd, "skip_web": skip_web}
    return hashlib.sha256(json.dumps(relevant, sort_keys=True, default=str).encode()).hexdigest()


def restored(path: Path, resume: bool) -> dict:
    if not resume:
        return {}
    record = load_json(path)
    # A successful Nmap phase must still have its original raw XML available.
    if record.get("status") != "complete":
        return {}
    xml_file = record.get("xml_file")
    if xml_file and not Path(xml_file).is_file():
        return {}
    return record


def log(msg: str) -> None:
    print(msg, flush=True)


async def pipeline(args: argparse.Namespace) -> int:
    target = validate_target(args.target)
    ports = validate_ports(args.ports)
    cfg = load_config(args.config.resolve())
    overrides = {}
    if args.wordlist is not None:
        overrides["wordlist"] = args.wordlist.expanduser().resolve()
    if args.min_rate is not None:
        overrides["min_rate"] = args.min_rate
    if args.threads is not None:
        overrides["threads"] = args.threads
    if overrides:
        cfg = dataclasses.replace(cfg, **overrides)
    if cfg.min_rate < 1 or cfg.min_rate > 100000 or cfg.threads < 1 or cfg.threads > 100:
        raise ValueError("--min-rate o --threads fuori limite")
    output = (args.output or (Path("reports") / target.replace(":", "_"))).expanduser().resolve()
    output.mkdir(parents=True, exist_ok=True)
    fingerprint_id = key_for(target, ports, cfg, args.nvd, args.skip_web)
    manifest_path = output / "run_manifest.json"
    previous = load_json(manifest_path)
    if args.resume and previous.get("fingerprint") != fingerprint_id:
        raise ValueError("--resume: target/configurazione diversi dalla sessione salvata; utilizzare un'altra cartella --output")
    atomic_json(manifest_path, {"target": target, "fingerprint": fingerprint_id, "updated_at": utc_now(), "config": dataclasses.asdict(cfg)})
    errors: list[str] = []
    if not exists("nmap"):
        errors.append("nmap mancante: sudo apt install nmap")
    log(f"[1/4] Discovery TCP su {target}...")
    p1 = restored(output / "01_nmap_discovery.json", args.resume)
    if not p1:
        p1 = await discover(target, ports, cfg, output)
    if p1.get("status") != "complete":
        errors.append("Fase Nmap discovery fallita: " + p1.get("execution", {}).get("error", "errore sconosciuto"))
    open_ports = open_tcp_ports(p1.get("parsed", {}))
    log(f"      Porte trovate: {', '.join(map(str, open_ports)) or 'nessuna'}")
    log("[2/4] Fingerprint servizi, script default e vulners...")
    p2 = restored(output / "02_nmap_services.json", args.resume)
    if not p2:
        if p1.get("status") == "complete":
            p2 = await fingerprint(target, open_ports, cfg, output)
        else:
            p2 = phase_checkpoint(output / "02_nmap_services.json", "skipped", parsed={}, note="Fase 1 non completata")
    if p2.get("status") == "failed":
        errors.append("Fase Nmap servizi fallita: " + p2.get("execution", {}).get("error", "errore sconosciuto"))
    parsed = p2.get("parsed", {}) if p2.get("status") == "complete" else p1.get("parsed", {})
    log(f"[3/4] Web enumeration: {len(web_services(parsed))} servizi rilevati...")
    web_path = output / "03_web.json"
    web_record = restored(web_path, args.resume)
    if not web_record:
        if args.skip_web:
            web_record = phase_checkpoint(web_path, "complete", services=[], note="Web enumeration disabilitata")
        else:
            # Persist after EACH port, not only after the entire web phase.
            pending = {x["port"]: x for x in load_json(web_path).get("services", []) if x.get("port") is not None} if args.resume else {}
            state_lock = asyncio.Lock()
            async def completed(service: dict) -> None:
                async with state_lock:
                    pending[service["port"]] = service
                    phase_checkpoint(web_path, "partial", services=sorted(pending.values(), key=lambda x: x["port"]))
                    log(f"      Web porta {service['port']}: checkpoint salvato")
            todo_parsed = {"hosts": [{"ports": [p for h in parsed.get("hosts", []) for p in h.get("ports", []) if p.get("port") not in pending]}]}
            await scan_web(target, todo_parsed, cfg, output, on_complete=completed)
            web_record = phase_checkpoint(web_path, "complete", services=sorted(pending.values(), key=lambda x: x["port"]))
    web = web_record.get("services", [])
    for s in web:
        for phase in ("gobuster", "homepage_fingerprint"):
            part = s.get(phase, {})
            if part.get("status") in {"missing", "failed"}:
                errors.append(f"Porta {s.get('port', '?')} {phase}: {part.get('error') or part.get('execution', {}).get('error')}")
        for candidate in s.get("login_candidates", []):
            fp = candidate.get("fingerprint", {})
            if fp.get("status") in {"missing", "failed"}:
                errors.append(f"Login {candidate.get('url', '?')} webanalyze: {fp.get('error') or fp.get('execution', {}).get('error')}")
    log("[4/4] SearchSploit, CVE e ranking RCE...")
    vulns_path = output / "04_vulnerabilities.json"
    vulns_record = restored(vulns_path, args.resume)
    if not vulns_record:
        results = await lookup(parsed, web, cfg, args.nvd)
        vulns_record = phase_checkpoint(vulns_path, "complete", **results)
    if not exists("searchsploit"):
        errors.append("searchsploit mancante: sudo apt install exploitdb")
    paths = write_report(output, target, p1, p2, web, vulns_record, errors)
    log(f"\nReport JSON: {paths[0]}\nReport Markdown: {paths[1]}")
    log(f"RCE candidati (non verificati): {len(vulns_record.get('rce_candidates', []))}; errori/avvisi: {len(errors)}")
    return 0 if p1.get("status") == "complete" and p2.get("status") == "complete" else 2


def main() -> None:
    p = parser()
    args = p.parse_args()
    if not args.authorized:
        p.error("Aggiungere --authorized per confermare che il target e' un lab/CTF autorizzato")
    try:
        code = asyncio.run(pipeline(args))
    except (ValueError, OSError) as exc:
        print(f"ERRORE: {exc}", file=sys.stderr)
        code = 2
    except KeyboardInterrupt:
        print("\nInterrotto: i checkpoint già salvati sono disponibili; usare --resume.", file=sys.stderr)
        code = 130
    raise SystemExit(code)
