"""Configuration and input validation (Python 3.11 stdlib only)."""
from __future__ import annotations

import ipaddress
import re
import tomllib
from dataclasses import dataclass
from pathlib import Path


@dataclass(frozen=True)
class Config:
    wordlist: Path
    webanalyze_apps: Path
    min_rate: int = 2000
    nmap_timeout: int = 900
    command_timeout: int = 180
    http_timeout: int = 10
    threads: int = 10
    max_web_concurrency: int = 3
    max_login_paths: int = 6
    max_search_terms: int = 25
    gobuster_timeout: int = 180
    max_body_bytes: int = 524288
    verify_tls: bool = False
    nvd_enabled: bool = False
    nvd_max_queries: int = 6


def _relative_path(value: str, base: Path) -> Path:
    p = Path(value).expanduser()
    return p if p.is_absolute() else (base / p).resolve()


def load_config(path: Path) -> Config:
    if not path.is_file():
        raise ValueError(f"File di configurazione non trovato: {path}")
    with path.open("rb") as f:
        data = tomllib.load(f)
    scan = data.get("scan", {})
    web = data.get("web", {})
    lookup = data.get("lookup", {})
    paths = data.get("paths", {})
    cfg = Config(
        wordlist=_relative_path(paths.get("wordlist", "/usr/share/seclists/Discovery/Web-Content/common.txt"), path.parent),
        webanalyze_apps=_relative_path(paths.get("webanalyze_apps", "technologies.json"), path.parent),
        min_rate=int(scan.get("min_rate", 2000)),
        nmap_timeout=int(scan.get("nmap_timeout", 900)),
        command_timeout=int(scan.get("command_timeout", 180)),
        http_timeout=int(web.get("http_timeout", 10)),
        threads=int(web.get("threads", 10)),
        max_web_concurrency=int(web.get("max_concurrency", 3)),
        max_login_paths=int(web.get("max_login_paths", 6)),
        max_search_terms=int(lookup.get("max_search_terms", 25)),
        gobuster_timeout=int(web.get("gobuster_timeout", 180)),
        max_body_bytes=int(web.get("max_body_bytes", 524288)),
        verify_tls=bool(web.get("verify_tls", False)),
        nvd_enabled=bool(lookup.get("nvd_enabled", False)),
        nvd_max_queries=int(lookup.get("nvd_max_queries", 6)),
    )
    for k in ("min_rate", "nmap_timeout", "command_timeout", "http_timeout", "threads", "max_web_concurrency", "max_login_paths", "max_search_terms", "gobuster_timeout", "max_body_bytes", "nvd_max_queries"):
        if getattr(cfg, k) < 1:
            raise ValueError(f"config: {k} deve essere maggiore di zero")
    if cfg.min_rate > 100000 or cfg.threads > 100 or cfg.max_web_concurrency > 20:
        raise ValueError("Rate/thread/concurrency fuori dai limiti previsti")
    return cfg


def validate_target(value: str) -> str:
    """Accept IP addresses (IPv4/IPv6) or DNS hostnames, not URLs or flags."""
    value = value.strip()
    try:
        ipaddress.ip_address(value)
        return value
    except ValueError:
        pass
    if len(value) > 253 or not value or value.startswith("-") or ":" in value:
        raise ValueError("Target non valido: passare un solo IP o hostname, non un URL")
    labels = value.rstrip(".").split(".")
    if not all(0 < len(s) < 64 and re.fullmatch(r"[A-Za-z0-9](?:[A-Za-z0-9-]*[A-Za-z0-9])?", s) for s in labels):
        raise ValueError("Hostname non valido")
    return value.rstrip(".")


def validate_ports(value: str | None) -> str:
    if value is None:
        return "-"  # Nmap's -p- syntax is constructed separately
    parts = value.split(",")
    if not parts or len(parts) > 200:
        raise ValueError("Troppe voci nel range porte")
    for part in parts:
        if not re.fullmatch(r"\d{1,5}(?:-\d{1,5})?", part):
            raise ValueError("Range porte non valido (esempio: 22,80,8000-9000)")
        nums = [int(v) for v in part.split("-")]
        if any(x < 1 or x > 65535 for x in nums) or nums[0] > nums[-1]:
            raise ValueError("Porta fuori range o intervallo invertito")
    return value
