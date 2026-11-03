"""Non-exploiting candidate lookup via SearchSploit and optional NVD v2 API."""
from __future__ import annotations

import asyncio
import json
import os
import re
import urllib.error
import urllib.parse
import urllib.request
from collections import defaultdict
from typing import Any

from .config import Config
from .utils import exists, run_command

RCE_RE = re.compile(r"\b(?:RCE|remote code execution|remote command execution|arbitrary code execution|arbitrary command execution|OS command injection|command injection)\b", re.I)
CVE_RE = re.compile(r"\bCVE-\d{4}-\d{4,8}\b", re.I)


def technologies_from_scan(nmap: dict, web: list[dict]) -> list[dict]:
    """Flatten observations but retain where the evidence came from."""
    techs: dict[tuple[str, str], dict] = {}

    def record(name: str, version: str, evidence: str) -> None:
        name, version = str(name).strip(), str(version).strip()
        if not name or len(name) > 100 or len(version) > 60:
            return
        key = (name.lower(), version.lower())
        if key not in techs:
            techs[key] = {"name": name, "version": version, "evidence": []}
        if evidence not in techs[key]["evidence"]:
            techs[key]["evidence"].append(evidence)

    for host in nmap.get("hosts", []):
        for port in host.get("ports", []):
            svc = port.get("service", {})
            product = svc.get("product") or svc.get("name") or ""
            record(product, svc.get("version", ""), f"nmap:{port['port']}")
    for item in web:
        if "port" not in item:
            continue
        fingerprints = [(item.get("homepage_fingerprint", {}), "home")]
        fingerprints.extend((p.get("fingerprint", {}), p.get("url", "login")) for p in item.get("login_candidates", []))
        for fingerprint, url in fingerprints:
            for t in fingerprint.get("technologies", []):
                record(t.get("name", ""), t.get("version", ""), f"web:{item['port']}:{url}")
    return list(techs.values())


def cves_from_nmap(nmap: dict) -> list[dict]:
    found: dict[str, dict] = {}
    for host in nmap.get("hosts", []):
        for port in host.get("ports", []):
            for script in port.get("scripts", []):
                if script.get("id") != "vulners":
                    continue
                for cve in script.get("cves", []):
                    if not CVE_RE.fullmatch(cve):
                        continue
                    entry = found.setdefault(cve, {
                        "id": cve, "source": "nmap_vulners", "title": cve,
                        "description": "CVE candidato segnalato da NSE vulners: tipo non verificato",
                        "is_rce": False, "rce_evidence": "unknown", "ports": [], "reference": f"https://nvd.nist.gov/vuln/detail/{cve}",
                    })
                    if port["port"] not in entry["ports"]:
                        entry["ports"].append(port["port"])
    return list(found.values())


def _search_query(term: dict) -> list[str]:
    # A service banner is untrusted input. Use only benign query tokens.
    name = re.sub(r"[^\w. +_-]", " ", term["name"], flags=re.UNICODE).strip()[:80]
    version = re.sub(r"[^0-9A-Za-z_.-]", "", term["version"])[:40]
    if not name or name.startswith("-"):
        return []
    return [name, version] if version else [name]


async def query_searchsploit(tech: dict, timeout: int) -> dict:
    query = _search_query(tech)
    if not query:
        return {"technology": tech, "status": "skipped", "matches": []}
    argv = ["searchsploit", "-j", "-t", *query]
    result = await run_command(argv, timeout)
    # SearchSploit may use a non-zero exit code for empty findings, but still return valid JSON.
    try:
        data = json.loads(result.get("stdout", ""))
    except json.JSONDecodeError:
        data = {}
    matches = data.get("RESULTS_EXPLOIT", []) if isinstance(data, dict) else []
    findings = []
    for entry in matches if isinstance(matches, list) else []:
        if not isinstance(entry, dict):
            continue
        title = str(entry.get("Title") or "")
        edb_id = str(entry.get("EDB-ID", ""))
        finding = {
            "source": "searchsploit",
            "title": title,
            "id": edb_id,
            "path": str(entry.get("Path", "")),
            "reference": f"https://www.exploit-db.com/exploits/{edb_id}" if edb_id.isdigit() else None,
            "is_rce": bool(RCE_RE.search(title)),
            "rce_evidence": "title" if RCE_RE.search(title) else "not_indicated",
            "technology": tech,
        }
        findings.append(finding)
    return {"technology": tech, "status": "complete" if result.get("ok") or matches else "failed", "execution": result, "raw_json": data, "matches": findings}


def _nvd_request(tech: dict, timeout: int, key: str | None) -> dict:
    phrase = " ".join(_search_query(tech))
    if not phrase:
        return {"technology": tech, "status": "skipped", "matches": []}
    url = "https://services.nvd.nist.gov/rest/json/cves/2.0?" + urllib.parse.urlencode({"keywordSearch": phrase, "resultsPerPage": 20})
    headers = {"User-Agent": "ctf-enum-lab/1.0", "Accept": "application/json"}
    if key:
        headers["apiKey"] = key
    try:
        with urllib.request.urlopen(urllib.request.Request(url, headers=headers), timeout=timeout) as response:
            data = json.load(response)
    except (urllib.error.URLError, ValueError, TimeoutError, OSError) as exc:
        return {"technology": tech, "status": "failed", "error": str(exc), "matches": []}
    matches = []
    for row in data.get("vulnerabilities", []):
        cve = row.get("cve", {})
        description = next((x.get("value", "") for x in cve.get("descriptions", []) if x.get("lang") == "en"), "")
        ident = cve.get("id", "")
        if not CVE_RE.fullmatch(ident) or cve.get("vulnStatus") == "Rejected":
            continue
        metrics = cve.get("metrics", {})
        scores = [v.get("cvssData", {}).get("baseScore") for entries in metrics.values() if isinstance(entries, list) for v in entries if isinstance(v, dict)]
        scores = [s for s in scores if isinstance(s, (int, float))]
        matches.append({
            "source": "nvd", "id": ident, "title": ident,
            "description": description, "is_rce": bool(RCE_RE.search(description)),
            "rce_evidence": "nvd_description" if RCE_RE.search(description) else "not_indicated",
            "cvss": max(scores, default=None),
            "reference": f"https://nvd.nist.gov/vuln/detail/{ident}",
            "technology": tech,
            "note": "Risultato da ricerca testuale: prodotto/versione e applicabilità da verificare manualmente",
        })
    return {"technology": tech, "status": "complete", "api_total_results": data.get("totalResults"), "matches": matches}


async def lookup(nmap: dict, web: list[dict], cfg: Config, with_nvd: bool = False) -> dict:
    technologies = technologies_from_scan(nmap, web)
    # Favor observations with version numbers, to avoid overbroad searches.
    selected = sorted(technologies, key=lambda x: (not bool(x["version"]), x["name"].lower()))[:cfg.max_search_terms]
    if exists("searchsploit"):
        sem = asyncio.Semaphore(4)

        async def search_one(t: dict) -> dict:
            async with sem:
                return await query_searchsploit(t, cfg.command_timeout)

        searches = await asyncio.gather(*(search_one(t) for t in selected))
    else:
        searches = [{"status": "missing", "error": "searchsploit mancante: sudo apt install exploitdb", "technology": t, "matches": []} for t in selected]
    nvd_matches: list[dict] = []
    if with_nvd or cfg.nvd_enabled:
        # NVD has strict rate limits. Calls are intentionally serial.
        key = os.environ.get("NVD_API_KEY")
        for idx, tech in enumerate(selected[:cfg.nvd_max_queries]):
            if idx:
                await asyncio.sleep(1 if key else 6.5)
            nvd_matches.append(await asyncio.to_thread(_nvd_request, tech, cfg.http_timeout, key))
    findings = cves_from_nmap(nmap)
    for result in searches + nvd_matches:
        findings.extend(result.get("matches", []))
    # Title says "remote" alone is NOT proof of code execution.
    findings.sort(key=lambda f: (not f["is_rce"], -(f.get("cvss") or 0), f.get("title", "")))
    return {
        "technologies": technologies,
        "searched_technologies": selected,
        "searchsploit": searches,
        "nvd": nvd_matches,
        "findings": findings,
        "rce_candidates": [f for f in findings if f["is_rce"]],
        "warning": "CVE, PoC e versioni sono indizi, non conferma di vulnerabilita: verificare CPE, patch e prerequisiti.",
    }
