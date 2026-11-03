"""Machine-readable final report and readable Markdown summary."""
from __future__ import annotations

from pathlib import Path
from .utils import atomic_json, utc_now


def _one(f: dict) -> str:
    title = str(f.get("title", f.get("id", "?"))).replace("\n", " ").replace("|", "\\|")
    reference = f.get("reference") or ""
    source = f.get("source", "?")
    tech = f.get("technology") or {}
    scope = ", ".join(map(str, f.get("ports", []))) or f"{tech.get('name', '—')} {tech.get('version', '')}".strip()
    return f"| {source} | {title[:110]} | {scope} | {reference} |"


def build_markdown(target: str, phase1: dict, phase2: dict, web: list[dict], vulns: dict, errors: list[str]) -> str:
    ports = [p for h in phase2.get("parsed", {}).get("hosts", []) for p in h.get("ports", [])]
    if not ports:
        ports = [p for h in phase1.get("parsed", {}).get("hosts", []) for p in h.get("ports", [])]
    lines = [f"# Enumerazione CTF — `{target}`", "", f"Generato: {utc_now()}", "", "## Porte e servizi", "", "| Porta | Servizio | Prodotto | Versione |", "|---|---|---|---|"]
    for p in ports:
        svc = p.get("service", {})
        fields = [f"{p['port']}/{p['protocol']}", svc.get("name", "?"), svc.get("product", ""), svc.get("version", "")]
        lines.append("| " + " | ".join(str(x).replace("|", "\\|").replace("\n", " ") for x in fields) + " |")
    if not ports:
        lines.append("| — | Nessuna porta rilevata | — | — |")
    lines += ["", "## Candidati RCE (prima i risultati con indicatori espliciti)", "", "| Fonte | CVE / exploit candidato | Tecnologia / porte | Riferimento |", "|---|---|---|---|"]
    candidates = vulns.get("rce_candidates", [])
    lines += [_one(f) for f in candidates[:100]] if candidates else ["| — | Nessun candidato RCE esplicito | — | — |"]
    lines += ["", "## Altri risultati da verificare", "", "| Fonte | CVE / exploit candidato | Tecnologia / porte | Riferimento |", "|---|---|---|---|"]
    others = [f for f in vulns.get("findings", []) if not f["is_rce"]]
    lines += [_one(f) for f in others[:100]] if others else ["| — | Nessun risultato ulteriore | — | — |"]
    lines += ["", "## Enumerazione web", ""]
    for item in web:
        lines.append(f"### {item.get('base_url', 'Porta ' + str(item.get('port', '?')))}")
        directory = item.get("gobuster", {})
        paths = directory.get("paths", [])
        lines.append(f"- Gobuster: **{directory.get('status', '?')}**; path trovati: **{len(paths)}**")
        for path in paths[:40]:
            lines.append(f"  - `{path['path']}` (HTTP {path['status']})")
        if len(paths) > 40:
            lines.append(f"  - ... altri {len(paths) - 40} (vedi JSON)")
        fp = item.get("homepage_fingerprint", {})
        techs = fp.get("technologies", [])
        lines.append("- Fingerprint home: " + (", ".join(f"{t['name']} {t['version']}".strip() for t in techs) if techs else "nessuna tecnologia riconosciuta"))
        for login in item.get("login_candidates", []):
            technologies = login["fingerprint"].get("technologies", [])
            lines.append(f"- Login `{login['url']}`; campo password: **{login['page'].get('password_field', False)}**; stack: " + (", ".join(f"{t['name']} {t['version']}".strip() for t in technologies) or "non rilevato"))
        lines.append("")
    if not web:
        lines += ["Nessun servizio HTTP riconosciuto.", ""]
    lines += ["## Avvertenze", "", "- I risultati SearchSploit e NVD sono **candidati**, non dimostrano che la versione sia vulnerabile o che una RCE sia sfruttabile.", "- NVD è una ricerca testuale e può includere CVE non applicabili.", "- Gli output XML Nmap e i file Gobuster sono conservati come allegati grezzi nella cartella del report.", ""]
    if errors:
        lines += ["## Errori e fasi parziali", ""] + [f"- {e}" for e in errors] + [""]
    return "\n".join(lines)


def write_report(output: Path, target: str, p1: dict, p2: dict, web: list[dict], vulns: dict, errors: list[str]) -> tuple[Path, Path]:
    data = {
        "target": target, "generated_at": utc_now(),
        "phase1": p1, "phase2": p2, "web": web, "vulnerabilities": vulns,
        "errors": errors,
    }
    json_path, md_path = output / "report.json", output / "report.md"
    atomic_json(json_path, data)
    md_path.write_text(build_markdown(target, p1, p2, web, vulns, errors), encoding="utf-8")
    return json_path, md_path
