"""Nmap two-pass scanning and proper ElementTree XML parsing."""
from __future__ import annotations

import re
import xml.etree.ElementTree as ET
from pathlib import Path
from .config import Config
from .utils import run_command, phase_checkpoint

CVE_PATTERN = re.compile(r"\bCVE-\d{4}-\d{4,8}\b", re.IGNORECASE)


def _nse_node(node: ET.Element) -> dict:
    return {
        "tag": node.tag,
        "attributes": dict(node.attrib),
        "value": (node.text or "").strip(),
        "children": [_nse_node(x) for x in node],
    }


def _structured_cves(node: ET.Element) -> set[str]:
    """Extract CVE identifiers from parsed XML element values/attrs, not from XML text."""
    found: set[str] = set()
    for child in node.iter():
        if child.tag in {"elem", "table"}:
            for txt in [child.attrib.get("key", ""), child.text or ""]:
                found.update(x.upper() for x in CVE_PATTERN.findall(txt))
    return found


def parse_nmap_xml(path: Path) -> dict:
    root = ET.parse(path).getroot()
    if root.tag != "nmaprun":
        raise ValueError("XML non riconosciuto come output Nmap")
    result = {"scanner": root.attrib.get("scanner"), "args": root.attrib.get("args"), "hosts": []}
    for host in root.findall("host"):
        record: dict = {
            "status": (host.find("status").attrib if host.find("status") is not None else {}),
            "addresses": [x.attrib for x in host.findall("address")],
            "hostnames": [x.attrib for x in host.findall("hostnames/hostname")],
            "ports": [],
            "hostscripts": [],
        }
        for script in host.findall("hostscript/script"):
            record["hostscripts"].append({"id": script.get("id"), "output": script.get("output", ""), "xml": [_nse_node(x) for x in script]})
        for port in host.findall("ports/port"):
            state_node = port.find("state")
            state = state_node.attrib if state_node is not None else {}
            if state.get("state") != "open":
                continue
            svc_node = port.find("service")
            service = dict(svc_node.attrib) if svc_node is not None else {}
            service["cpes"] = [x.text for x in svc_node.findall("cpe") if x.text] if svc_node is not None else []
            scripts = []
            for script in port.findall("script"):
                scripts.append({
                    "id": script.get("id", ""),
                    "output": script.get("output", ""),
                    "xml": [_nse_node(x) for x in script],
                    "cves": sorted(_structured_cves(script) or {c.upper() for c in CVE_PATTERN.findall(script.get("output", ""))}),
                })
            record["ports"].append({
                "protocol": port.get("protocol", "tcp"),
                "port": int(port.get("portid", "0")),
                "state": state,
                "service": service,
                "scripts": scripts,
            })
        result["hosts"].append(record)
    return result


def open_tcp_ports(parsed: dict) -> list[int]:
    return sorted({p["port"] for h in parsed.get("hosts", []) for p in h.get("ports", []) if p["protocol"] == "tcp"})


async def discover(target: str, ports: str, cfg: Config, output: Path) -> dict:
    xml_file = output / "01_nmap_discovery.xml"
    argv = ["nmap", "-Pn", "-n", "-T4", "--open", "--min-rate", str(cfg.min_rate)]
    argv.extend(["-p-"] if ports == "-" else ["-p", ports])
    argv.extend(["-oX", str(xml_file), target])
    execution = await run_command(argv, cfg.nmap_timeout)
    record = {"command": argv, "execution": execution, "xml_file": str(xml_file), "parsed": {}}
    if execution.get("ok") and xml_file.is_file():
        try:
            record["parsed"] = parse_nmap_xml(xml_file)
        except (ET.ParseError, ValueError, OSError) as exc:
            execution["ok"] = False
            execution["error"] = f"XML Nmap fase 1 non valido: {exc}"
    return phase_checkpoint(output / "01_nmap_discovery.json", "complete" if execution.get("ok") else "failed", **record)


async def fingerprint(target: str, ports: list[int], cfg: Config, output: Path) -> dict:
    xml_file = output / "02_nmap_services.xml"
    if not ports:
        return phase_checkpoint(output / "02_nmap_services.json", "complete", command=[], execution={"ok": True}, xml_file=None, parsed={"hosts": []}, note="Nessuna porta TCP aperta")
    argv = ["nmap", "-Pn", "-n", "-sV", "--script", "default,vulners", "-p", ",".join(map(str, ports)), "-oX", str(xml_file), target]
    execution = await run_command(argv, cfg.nmap_timeout)
    record = {"command": argv, "execution": execution, "xml_file": str(xml_file), "parsed": {}}
    if execution.get("ok") and xml_file.is_file():
        try:
            record["parsed"] = parse_nmap_xml(xml_file)
        except (ET.ParseError, ValueError, OSError) as exc:
            execution["ok"] = False
            execution["error"] = f"XML Nmap fase 2 non valido: {exc}"
    return phase_checkpoint(output / "02_nmap_services.json", "complete" if execution.get("ok") else "failed", **record)
