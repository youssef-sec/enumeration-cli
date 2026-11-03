"""Subprocesses and durable checkpoints."""
from __future__ import annotations

import asyncio
import json
import os
import shutil
import signal
import tempfile
from datetime import datetime, timezone
from pathlib import Path
from typing import Any


def utc_now() -> str:
    return datetime.now(timezone.utc).isoformat()


def exists(executable: str) -> bool:
    return shutil.which(executable) is not None


def atomic_json(path: Path, data: Any) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    fd, name = tempfile.mkstemp(prefix=f".{path.name}.", dir=path.parent)
    try:
        with os.fdopen(fd, "w", encoding="utf-8") as f:
            json.dump(data, f, indent=2, ensure_ascii=False, default=str)
            f.write("\n")
            f.flush()
            os.fsync(f.fileno())
        os.replace(name, path)
    finally:
        if os.path.exists(name):
            os.unlink(name)


def load_json(path: Path) -> dict:
    if not path.is_file():
        return {}
    try:
        with path.open(encoding="utf-8") as f:
            obj = json.load(f)
        return obj if isinstance(obj, dict) else {}
    except (OSError, ValueError):
        return {}


def phase_checkpoint(path: Path, status: str, **data: Any) -> dict:
    record = {"status": status, "updated_at": utc_now(), **data}
    atomic_json(path, record)
    return record


async def run_command(argv: list[str], timeout: int, cwd: Path | None = None) -> dict:
    """Never invokes a shell; kills the entire child process group on timeout/cancel."""
    if not exists(argv[0]):
        return {"ok": False, "error": f"Tool mancante: {argv[0]} (non presente nel PATH)", "argv": argv}
    try:
        proc = await asyncio.create_subprocess_exec(
            *argv,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE,
            cwd=cwd,
            start_new_session=True,
        )
        try:
            out, err = await asyncio.wait_for(proc.communicate(), timeout=timeout)
        except (asyncio.TimeoutError, asyncio.CancelledError) as exc:
            try:
                os.killpg(proc.pid, signal.SIGKILL)
            except ProcessLookupError:
                pass
            await proc.communicate()
            if isinstance(exc, asyncio.CancelledError):
                raise
            return {"ok": False, "error": f"Timeout dopo {timeout}s", "argv": argv}
        stdout = out.decode("utf-8", "replace")
        stderr = err.decode("utf-8", "replace")
        return {
            "ok": proc.returncode == 0,
            "exit_code": proc.returncode,
            "stdout": stdout[:200000],
            "stderr": stderr[:20000],
            "argv": argv,
            "error": "" if proc.returncode == 0 else (stderr.strip() or stdout.strip() or f"Codice uscita {proc.returncode}")[:2000],
        }
    except OSError as exc:
        return {"ok": False, "error": f"Impossibile eseguire {argv[0]}: {exc}", "argv": argv}
