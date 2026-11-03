"""Bounded web enumeration: Gobuster, Webanalyze, HTML login detection."""
from __future__ import annotations

import asyncio
import ipaddress
import json
import re
import ssl
import urllib.error
import urllib.parse
import urllib.request
from html.parser import HTMLParser
from pathlib import Path
from typing import Any, Callable, Awaitable

from .config import Config
from .utils import exists, run_command

WEB_PORTS = {80, 81, 443, 3000, 3001, 5000, 5001, 7001, 8000, 8008, 8080, 8081, 8181, 8443, 8888, 9000, 9090, 9443, 10000}
TLS_PORTS = {443, 8443, 9443}
LOGIN_PATH_RE = re.compile(r"(?:^|/)(?:login|log-in|signin|sign-in|admin|auth|session|wp-login(?:\.php)?|user/login)(?:/|\.|$|\?)", re.I)
GOBUSTER_LINE = re.compile(r"^(?P<path>/\S+)\s+\(Status:\s*(?P<status>\d+)\)")


def web_services(parsed: dict) -> list[dict]:
    seen = set()
    found = []
    for host in parsed.get("hosts", []):
        for p in host.get("ports", []):
            if p.get("protocol") != "tcp":
                continue
            port = p["port"]
            svc = p.get("service", {})
            name = str(svc.get("name", "")).lower()
            if port not in WEB_PORTS and "http" not in name and "https" not in name:
                continue
            if port in seen:
                continue
            seen.add(port)
            scheme = "https" if port in TLS_PORTS or svc.get("tunnel") == "ssl" or "https" in name or name.startswith("ssl/http") else "http"
            found.append({"port": port, "scheme": scheme, "service": svc})
    return found


def base_url(target: str, service: dict) -> str:
    try:
        if ipaddress.ip_address(target).version == 6:
            target = f"[{target}]"
    except ValueError:
        pass
    return f"{service['scheme']}://{target}:{service['port']}"


class LoginHTML(HTMLParser):
    def __init__(self) -> None:
        super().__init__(convert_charrefs=True)
        self.password_field = False
        self.links: list[str] = []
        self.form_actions: list[str] = []

    def handle_starttag(self, tag: str, attrs: list[tuple[str, str | None]]) -> None:
        data = dict(attrs)
        if tag == "input" and (data.get("type") or "").lower() == "password":
            self.password_field = True
        if tag == "form" and data.get("action"):
            self.form_actions.append(data["action"] or "")
        if tag == "a" and data.get("href"):
            self.links.append(data["href"] or "")


def same_origin_url(origin: str, value: str) -> str | None:
    absolute = urllib.parse.urljoin(origin + "/", value)
    base = urllib.parse.urlsplit(origin)
    candidate = urllib.parse.urlsplit(absolute)
    if candidate.scheme not in {"http", "https"}:
        return None
    default_port = {"http": 80, "https": 443}
    base_port = base.port or default_port[base.scheme]
    dest_port = candidate.port or default_port[candidate.scheme]
    if (base.scheme, base.hostname, base_port) != (candidate.scheme, candidate.hostname, dest_port):
        return None
    return urllib.parse.urlunsplit((candidate.scheme, candidate.netloc, candidate.path or "/", candidate.query, ""))


class SameOriginRedirect(urllib.request.HTTPRedirectHandler):
    def __init__(self, origin: str) -> None:
        self.origin = origin

    def redirect_request(self, req: Any, fp: Any, code: int, msg: str, headers: Any, newurl: str) -> Any:
        if same_origin_url(self.origin, newurl) is None:
            raise urllib.error.HTTPError(req.full_url, code, "Redirect fuori scope bloccato", headers, fp)
        return super().redirect_request(req, fp, code, msg, headers, newurl)


def _fetch(url: str, origin: str, cfg: Config) -> dict:
    context = ssl.create_default_context() if cfg.verify_tls else ssl._create_unverified_context()
    opener = urllib.request.build_opener(SameOriginRedirect(origin), urllib.request.HTTPSHandler(context=context))
    request = urllib.request.Request(url, headers={"User-Agent": "CTF-Enum/1.0", "Accept": "text/html,*/*"})
    try:
        with opener.open(request, timeout=cfg.http_timeout) as response:
            payload = response.read(cfg.max_body_bytes + 1)
            mime = response.headers.get("Content-Type", "")
            truncated = len(payload) > cfg.max_body_bytes
            html = payload[:cfg.max_body_bytes].decode("utf-8", "replace") if "html" in mime.lower() or payload.lstrip().startswith(b"<") else ""
            doc = LoginHTML()
            if html:
                doc.feed(html)
            return {
                "url": response.url,
                "status": response.status,
                "content_type": mime,
                "password_field": doc.password_field,
                "links": doc.links[:100],
                "form_actions": doc.form_actions[:30],
                "bytes_read": len(payload),
                "truncated": truncated,
                "error": None,
            }
    except (urllib.error.URLError, ValueError, TimeoutError, OSError) as exc:
        return {"url": url, "error": str(exc), "password_field": False, "links": [], "form_actions": []}


async def fetch_page(url: str, origin: str, cfg: Config) -> dict:
    return await asyncio.to_thread(_fetch, url, origin, cfg)


def parse_gobuster_text(text: str, base: str) -> list[dict]:
    paths = []
    for line in text.splitlines():
        m = GOBUSTER_LINE.match(line.strip())
        if not m:
            continue
        safe = same_origin_url(base, m.group("path"))
        if safe:
            paths.append({"path": m.group("path"), "status": int(m.group("status")), "url": safe})
    return paths


def parse_webanalyze_json(raw: str) -> tuple[Any, list[dict]]:
    """Accept JSON list, single object, or JSON-lines across Webanalyze versions."""
    try:
        loaded = json.loads(raw)
    except json.JSONDecodeError:
        loaded = []
        for line in raw.splitlines():
            try:
                loaded.append(json.loads(line))
            except json.JSONDecodeError:
                continue
    rows = loaded if isinstance(loaded, list) else [loaded]
    technologies = []
    for row in rows:
        if not isinstance(row, dict):
            continue
        matches = row.get("matches", [])
        if not isinstance(matches, list):
            continue
        for match in matches:
            if not isinstance(match, dict):
                continue
            name = match.get("app_name") or match.get("name") or match.get("app")
            if not isinstance(name, str) or not name:
                continue
            technologies.append({"name": name, "version": str(match.get("version") or ""), "url": row.get("host", "")})
    return loaded, technologies


async def gobuster(base: str, port: int, cfg: Config, output: Path) -> dict:
    if not exists("gobuster"):
        return {"status": "missing", "error": "gobuster mancante: sudo apt install gobuster", "paths": []}
    if not cfg.wordlist.is_file():
        return {"status": "missing", "error": f"Wordlist mancante: {cfg.wordlist} (installare seclists o usare --wordlist)", "paths": []}
    filename = output / f"03_gobuster_{port}.txt"
    args = ["gobuster", "dir", "-u", base, "-w", str(cfg.wordlist), "-t", str(cfg.threads), "--timeout", f"{cfg.http_timeout}s", "-q", "-o", str(filename)]
    if not cfg.verify_tls and base.startswith("https:"):
        args.append("-k")
    result = await run_command(args, cfg.gobuster_timeout)
    raw = filename.read_text(errors="replace") if filename.is_file() else result.get("stdout", "")
    return {"status": "complete" if result.get("ok") else "failed", "execution": result, "raw_file": str(filename), "paths": parse_gobuster_text(raw, base)}


async def webanalyze(url: str, cfg: Config) -> dict:
    if not exists("webanalyze"):
        return {"status": "missing", "error": "webanalyze mancante: installare con 'go install ...' (vedi README)", "technologies": []}
    if not cfg.webanalyze_apps.is_file():
        return {"status": "missing", "error": f"Definizioni Webanalyze assenti: {cfg.webanalyze_apps}; eseguire 'webanalyze -update' nella directory del progetto", "technologies": []}
    cmd = ["webanalyze", "-host", url, "-crawl", "0", "-output", "json", "-silent", "-apps", str(cfg.webanalyze_apps), "-search=false"]
    result = await run_command(cmd, cfg.command_timeout)
    raw, tech = parse_webanalyze_json(result.get("stdout", ""))
    return {"status": "complete" if result.get("ok") else "failed", "execution": result, "raw_json": raw, "technologies": tech, "url": url}


async def scan_service(target: str, service: dict, cfg: Config, output: Path) -> dict:
    port = service["port"]
    origin = base_url(target, service)
    # Long-running directory enumeration and homepage fingerprint execute concurrently.
    gob_task = asyncio.create_task(gobuster(origin, port, cfg, output))
    wa_task = asyncio.create_task(webanalyze(origin, cfg))
    home_task = asyncio.create_task(fetch_page(origin + "/", origin, cfg))
    directory, home_fp, homepage = await asyncio.gather(gob_task, wa_task, home_task)
    paths: set[str] = set()
    for link in homepage.get("links", []) + homepage.get("form_actions", []):
        link_url = same_origin_url(origin, link)
        if link_url and LOGIN_PATH_RE.search(urllib.parse.urlsplit(link_url).path):
            paths.add(link_url)
    for item in directory.get("paths", []):
        if LOGIN_PATH_RE.search(item["path"]):
            paths.add(item["url"])
    if homepage.get("password_field"):
        paths.add(origin + "/")
    login_urls = sorted(paths)[:cfg.max_login_paths]
    # Inspect login candidates, then repeat Wappalyzer on each (including login at /).
    login_pages = await asyncio.gather(*(fetch_page(url, origin, cfg) for url in login_urls))
    login_fps = await asyncio.gather(*(webanalyze(url, cfg) for url in login_urls))
    return {
        "port": port,
        "base_url": origin,
        "gobuster": directory,
        "homepage": homepage,
        "homepage_fingerprint": home_fp,
        "login_candidates": [{"url": url, "page": page, "fingerprint": fp} for url, page, fp in zip(login_urls, login_pages, login_fps)],
    }


async def scan_web(target: str, parsed: dict, cfg: Config, output: Path, on_complete: Callable[[dict], Awaitable[None]] | None = None) -> list[dict]:
    sem = asyncio.Semaphore(cfg.max_web_concurrency)

    async def one(service: dict) -> dict:
        async with sem:
            try:
                result = await scan_service(target, service, cfg, output)
            except Exception as exc:
                result = {"port": service["port"], "status": "failed", "error": str(exc)}
            if on_complete:
                await on_complete(result)
            return result

    return await asyncio.gather(*(one(s) for s in web_services(parsed)))
