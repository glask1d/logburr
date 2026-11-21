#!/usr/bin/env python3
"""Logburr, a local viewer for directory-fuzz logs.

Reads feroxbuster, ffuf (markdown), gobuster, and dirsearch-style output
and serves a filterable table on localhost. Nothing leaves the machine
until you press Run or Send to Burp.

    python3 logburr.py ~/scans/api
    python3 logburr.py ~/scans/api -i ~/scans/other/ffuf.md
    python3 logburr.py ~/scans/api -p 8877
    python3 logburr.py ~/scans/api --check
"""

from __future__ import annotations

import argparse
import html
import json
import re
import shutil
import socket
import ssl
import subprocess
import sys
import threading
import urllib.error
import urllib.parse
import urllib.request
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path

ANSI = re.compile(r"\x1b\[[0-9;]*[A-Za-z]")
FEROX_HIT = re.compile(
    r"^(\d{3})\s+([A-Z]+)\s+(\d+)l\s+(\d+)w\s+(\d+)c\s+(\S+)(?:\s+=>\s+(\S+))?\s*$"
)
GOBUSTER_HIT = re.compile(
    r"^(?:Found:\s*)?(\S+)\s+\(Status:\s*(\d{3})\)"
    r"(?:\s+\[Size:\s*(\d+)\])?(?:\s+\[-->\s*(\S+)\])?\s*$"
)
DIRSEARCH_HIT = re.compile(
    r"^(\d{3})\s+([\d.]+)\s*([KMGkmg]?B)\s+(\S+)(?:\s+->\s+(\S+))?\s*$"
)
SKIP_SUFFIXES = {".py", ".pyc", ".pyo"}


def clean(text: str) -> str:
    # ffuf's markdown report writes " as &#34;. Turn those back into characters.
    text = html.unescape(ANSI.sub("", text))
    return text.replace("\r\n", "\n").replace("\r", "\n")


def to_int(value: str | None) -> int | None:
    if value is None or value == "":
        return None
    try:
        return int(value)
    except ValueError:
        return None


def to_ms(value: str | None) -> float | None:
    if not value:
        return None
    raw = value.strip()
    try:
        if raw.endswith("ms"):
            return round(float(raw[:-2]), 3)
        if raw.endswith("s"):
            return round(float(raw[:-1]) * 1000, 3)
        return round(float(raw), 3)
    except ValueError:
        return None


def path_of(url: str, fallback: str = "") -> str:
    if url:
        parsed = urllib.parse.urlparse(url)
        if parsed.scheme and parsed.netloc:
            path = parsed.path or "/"
            if parsed.query:
                path += "?" + parsed.query
            return path
        if url.startswith("/"):
            return url
    if fallback:
        return fallback if fallback.startswith("/") else "/" + fallback
    return url


def unquote(value: str) -> str:
    value = value.strip()
    if len(value) >= 2 and value[0] == value[-1] and value[0] in "'\"":
        return value[1:-1]
    return value


def shell_single(value: str) -> str:
    return "'" + value.replace("'", "'\\''") + "'"


def ffuf_headers(command: str) -> list[str]:
    headers = []
    for match in re.finditer(r"(?:^|\s)(?:-H|--header)(?:\s+|=)(.+?)(?=\s+-\w|\s*$)", command):
        header = unquote(match.group(1))
        if header:
            headers.append(header)
    return headers


def build_curl(method: str, url: str, headers: list[str], data: str) -> str:
    if not url:
        return ""
    parts = ["curl"]
    if url.lower().startswith("https://"):
        parts.append("-k")
    if method and method.upper() != "GET":
        parts.extend(["-X", method.upper()])
    parts.append(shell_single(url))
    for header in headers:
        if header:
            parts.extend(["-H", shell_single(header)])
    if data:
        parts.extend(["-d", shell_single(data)])
    return " ".join(parts)


BURP_PROXY = "http://127.0.0.1:8080"
BURP_HOST = "127.0.0.1"
BURP_PORT = 8080


def header_map(lines: list[str]) -> dict[str, str]:
    headers: dict[str, str] = {}
    for line in lines:
        if ":" not in line:
            continue
        name, value = line.split(":", 1)
        name = name.strip()
        if not name or name.lower() in {"host", "content-length", "connection", "transfer-encoding"}:
            continue
        headers[name] = value.strip()
    return headers


class _KeepResponse(urllib.request.HTTPErrorProcessor):
    def http_response(self, request, response):  # noqa: ARG002
        return response

    https_response = http_response


def send_through_burp(method: str, url: str, header_lines: list[str], body: str) -> dict:
    parsed = urllib.parse.urlparse(url)
    if parsed.scheme not in {"http", "https"} or not parsed.netloc:
        return {"ok": False, "message": "This row has no http(s) URL."}
    try:
        socket.create_connection((BURP_HOST, BURP_PORT), timeout=2).close()
    except OSError:
        return {"ok": False, "message": "Nothing is listening on 127.0.0.1:8080."}

    verb = (method or "GET").upper()
    payload = body.encode("utf-8") if body else b""
    if verb in {"GET", "HEAD"} and not body:
        payload = None
    request = urllib.request.Request(url, data=payload, headers=header_map(header_lines), method=verb)
    context = ssl._create_unverified_context()
    opener = urllib.request.build_opener(
        urllib.request.ProxyHandler({"http": BURP_PROXY, "https": BURP_PROXY}),
        urllib.request.HTTPSHandler(context=context),
        _KeepResponse,
    )
    result: dict = {}
    done = threading.Event()

    def worker() -> None:
        try:
            with opener.open(request, timeout=180) as response:
                response.read(65536)
                result["status"] = getattr(response, "status", None) or response.getcode()
        except Exception as exc:  # noqa: BLE001
            result["error"] = str(exc)
        finally:
            done.set()

    threading.Thread(target=worker, daemon=True).start()
    if not done.wait(4):
        return {"ok": True, "message": "Sent to Burp on 127.0.0.1:8080. If Intercept is on, it is waiting there."}
    if "error" in result:
        return {"ok": False, "message": "Burp did not forward it. " + result["error"]}
    return {"ok": True, "message": f"Burp returned HTTP {result.get('status')}."}


SAFE_NAME = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._-]{0,80}$")
SAVE_SUFFIXES = {".txt", ".json", ".http", ".log", ".md", ".html"}


def checked_request(method: str, url: str, header_lines: list) -> tuple[str, str, list[str]] | None:
    parsed = urllib.parse.urlparse(url)
    if parsed.scheme not in {"http", "https"} or not parsed.netloc:
        return None
    if any(char in url for char in "\r\n\t "):
        return None
    headers = []
    for line in header_lines:
        if not isinstance(line, str) or any(char in line for char in "\r\n"):
            continue
        if ":" not in line:
            continue
        headers.append(line.strip())
    return (method or "GET").upper(), url, headers


def run_request(method: str, url: str, header_lines: list, body: str) -> dict:
    checked = checked_request(method, url, header_lines)
    if checked is None:
        return {"ok": False, "message": "This row has no http(s) URL."}
    verb, url, headers = checked
    curl = shutil.which("curl")
    if not curl:
        return {"ok": False, "message": "curl is not installed."}
    # Fixed argv, never a shell. --noproxy keeps this off the Burp listener.
    command = [curl, "-skS", "--noproxy", "*", "-D", "-", "--max-time", "30", "-X", verb, url]
    for header in headers:
        command.extend(["-H", header])
    if body and verb not in {"GET", "HEAD"}:
        command.extend(["--data-binary", body])
    try:
        completed = subprocess.run(command, capture_output=True, timeout=35)
    except subprocess.TimeoutExpired:
        return {"ok": False, "message": "The request timed out after 30s."}
    raw = completed.stdout.decode("utf-8", "replace")
    error = completed.stderr.decode("utf-8", "replace").strip()
    if completed.returncode != 0 and not raw:
        return {"ok": False, "message": error or f"curl exited {completed.returncode}"}
    truncated = len(raw) > 500_000
    if truncated:
        raw = raw[:500_000] + "\n… truncated"
    return {"ok": True, "raw": raw, "message": error or "Response received.", "truncated": truncated}


def save_response(directory: Path, name: str, text: str) -> dict:
    name = (name or "").strip() or "response.txt"
    if not SAFE_NAME.match(name):
        return {"ok": False, "message": "Use a simple file name, like ip6-localhost.http"}
    if Path(name).suffix.lower() not in SAVE_SUFFIXES:
        name += ".txt"
    if len(text) > 2_000_000:
        return {"ok": False, "message": "That response is too large to save."}
    root = directory.resolve()
    folder = (root / "responses").resolve()
    try:
        folder.relative_to(root)
    except ValueError:
        return {"ok": False, "message": "Could not save inside the log directory."}
    folder.mkdir(exist_ok=True)
    path = folder / name
    if path.is_symlink():
        return {"ok": False, "message": "That name is a link."}
    if path.is_dir():
        return {"ok": False, "message": "That name is a folder."}
    path.write_text(text, encoding="utf-8")
    return {"ok": True, "message": f"Saved {path}", "path": str(path)}


def empty_file(name: str, tool: str, meta: dict, rows: list, note: str = "", preview: str = "") -> dict:
    return {
        "name": name,
        "tool": tool,
        "meta": meta,
        "rows": rows,
        "note": note,
        "preview": preview,
    }


def detect(text: str) -> str:
    if not text.strip():
        return "empty"
    head = text[:8000]
    if "FFUF Report" in head or "FUZZ" in head and "Status Code" in head and "|" in head:
        return "ffuf"
    if "Configuration {" in head and "target_url" in head:
        return "ferox"
    if "Gobuster" in head or GOBUSTER_HIT.search(text):
        return "gobuster"
    return "generic"


def parse_ffuf(name: str, text: str) -> dict:
    command = ""
    when = ""
    match = re.search(r"Command line\s*:\s*`([^`]*)`", text)
    if match:
        command = match.group(1).strip()
    match = re.search(r"^\s*Time:\s*(.+)$", text, re.M)
    if match:
        when = match.group(1).strip()
    method = "GET"
    method_match = re.search(r"(?:^|\s)-X\s+([A-Za-z]+)", command)
    if method_match:
        method = method_match.group(1).upper()
    target = ""
    target_match = re.search(r"(?:^|\s)-u\s+(\S+)", command)
    if target_match:
        target = target_match.group(1)
    wordlist = ""
    wordlist_match = re.search(r"(?:^|\s)-w\s+(\S+)", command)
    if wordlist_match:
        wordlist = wordlist_match.group(1).split(",")[0]
    data_template = ""
    data_match = re.search(r"(?:^|\s)-d\s+('[^']*'|\"[^\"]*\"|\S+)", command)
    if data_match:
        data_template = data_match.group(1)
        if len(data_template) >= 2 and data_template[0] == data_template[-1] and data_template[0] in "'\"":
            data_template = data_template[1:-1]

    headers: list[str] | None = None
    rows: list[dict] = []
    for line in text.splitlines():
        stripped = line.strip()
        if not stripped.startswith("|"):
            continue
        cells = [cell.strip() for cell in stripped.strip("|").split("|")]
        if headers is None:
            if "URL" in cells and ("Status Code" in cells or "Status" in cells):
                headers = cells
            continue
        if cells and all(set(cell) <= set(":- ") for cell in cells):
            continue
        record = {headers[i]: cells[i] if i < len(cells) else "" for i in range(len(headers))}
        status = to_int(record.get("Status Code") or record.get("Status"))
        url = record.get("URL") or record.get("Url") or ""
        if status is None or not url:
            continue
        fuzz = record.get("FUZZ", "")
        # The POST body is the part that differs when every hit shares one URL.
        payload = data_template.replace("FUZZ", fuzz) if data_template else ""
        rows.append(
            {
                "status": status,
                "method": method,
                "lines": to_int(record.get("Content Lines")),
                "words": to_int(record.get("Content Words")),
                "bytes": to_int(record.get("Content Length")),
                "url": url,
                "path": path_of(url, fuzz),
                "payload": payload,
                "fuzz": fuzz,
                "position": record.get("Position") or "",
                "hash": record.get("Ffufhash") or record.get("FfufHash") or "",
                "redirect": record.get("Redirectlocation") or record.get("Redirect") or "",
                "ctype": record.get("Content Type") or "",
                "ms": to_ms(record.get("Duration")),
                "raw": stripped,
            }
        )
    return empty_file(
        name,
        "ffuf",
        {
            "target": target,
            "wordlist": wordlist,
            "command": command,
            "time": when,
            "method": method,
            "headers": ffuf_headers(command),
        },
        rows,
        "" if rows else "FFUF report with no result rows.",
    )


def parse_ferox(name: str, text: str) -> dict:
    target = ""
    wordlist = ""
    depth = ""
    target_match = re.search(r'target_url:\s*"([^"]*)"', text)
    if target_match:
        target = target_match.group(1)
    wordlist_match = re.search(r'wordlist:\s*\[\s*"([^"]*)"', text)
    if wordlist_match:
        wordlist = wordlist_match.group(1)
    depth_match = re.search(r"^\s+depth:\s*(\d+)\s*,", text, re.M)
    if depth_match:
        depth = depth_match.group(1)
    rows = []
    for line in text.splitlines():
        match = FEROX_HIT.match(line.strip())
        if not match:
            continue
        status, method, lines, words, size, url, redirect = match.groups()
        rows.append(
            {
                "status": int(status),
                "method": method,
                "lines": int(lines),
                "words": int(words),
                "bytes": int(size),
                "url": url,
                "path": path_of(url),
                "redirect": redirect or "",
                "ctype": "",
                "ms": None,
                "raw": line.strip(),
            }
        )
    note = ""
    if not rows:
        note = "Configuration only. No result lines."
    return empty_file(
        name,
        "feroxbuster",
        {"target": target, "wordlist": wordlist, "depth": depth},
        rows,
        note,
    )


def parse_gobuster(name: str, text: str) -> dict:
    target = ""
    target_match = re.search(r"^\[?\+?\]?\s*Url:\s*(\S+)", text, re.M | re.I)
    if not target_match:
        target_match = re.search(r"(?:^|\s)-u\s+(\S+)", text)
    if target_match:
        target = target_match.group(1)
    wordlist = ""
    wordlist_match = re.search(r"(?:^|\s)-w\s+(\S+)", text)
    if wordlist_match:
        wordlist = wordlist_match.group(1)
    rows = []
    for line in text.splitlines():
        match = GOBUSTER_HIT.match(line.strip())
        if not match:
            continue
        found, status, size, redirect = match.groups()
        url = found if "://" in found else ""
        rows.append(
            {
                "status": int(status),
                "method": "GET",
                "lines": None,
                "words": None,
                "bytes": to_int(size),
                "url": url or found,
                "path": path_of(url, found),
                "redirect": redirect or "",
                "ctype": "",
                "ms": None,
                "raw": line.strip(),
            }
        )
    note = ""
    if not text.strip():
        note = "This file is empty."
    elif not rows:
        note = "Gobuster log with no result lines."
    return empty_file(name, "gobuster", {"target": target, "wordlist": wordlist}, rows, note)


def scale_bytes(number: str, unit: str) -> int:
    value = float(number)
    unit = unit.lower()
    if unit == "kb":
        value *= 1024
    elif unit == "mb":
        value *= 1024 * 1024
    elif unit == "gb":
        value *= 1024 * 1024 * 1024
    return int(value)


def parse_generic(name: str, text: str) -> dict:
    rows = []
    for line in text.splitlines():
        stripped = line.strip()
        if not stripped or stripped.startswith("#"):
            continue
        match = DIRSEARCH_HIT.match(stripped)
        if match:
            status, size, unit, url, redirect = match.groups()
            rows.append(
                {
                    "status": int(status),
                    "method": "",
                    "lines": None,
                    "words": None,
                    "bytes": scale_bytes(size, unit),
                    "url": url,
                    "path": path_of(url),
                    "redirect": redirect or "",
                    "ctype": "",
                    "ms": None,
                    "raw": stripped,
                }
            )
            continue
        if "://" not in stripped and "(Status:" not in stripped:
            continue
        status_match = re.search(r"\b([1-5]\d{2})\b", stripped)
        url_match = re.search(r"https?://\S+", stripped)
        if not status_match or not url_match:
            continue
        url = url_match.group(0).rstrip(".,)")
        rows.append(
            {
                "status": int(status_match.group(1)),
                "method": "",
                "lines": None,
                "words": None,
                "bytes": None,
                "url": url,
                "path": path_of(url),
                "redirect": "",
                "ctype": "",
                "ms": None,
                "raw": stripped,
            }
        )
    preview = ""
    note = ""
    if not rows and text.strip():
        lines = text.splitlines()
        preview = "\n".join(lines[:80])
        if len(lines) > 80:
            preview += f"\n… {len(lines) - 80} more lines"
        note = "No fuzz hits recognized. Showing the start of the file."
    return empty_file(name, "text", {}, rows, note, preview)


def with_curl(parsed: dict) -> dict:
    templates = parsed.get("meta", {}).get("headers") or []
    for row in parsed["rows"]:
        fuzz = row.get("fuzz") or ""
        headers = [header.replace("FUZZ", fuzz) for header in templates]
        row["curl"] = build_curl(row.get("method") or "", row.get("url") or "", headers, row.get("payload") or "")
    return parsed


def parse_log(name: str, text: str) -> dict:
    text = clean(text)
    kind = detect(text)
    if kind == "empty":
        return empty_file(name, "empty", {}, [], "This file is empty.")
    if kind == "ffuf":
        return with_curl(parse_ffuf(name, text))
    if kind == "ferox":
        return with_curl(parse_ferox(name, text))
    if kind == "gobuster":
        return with_curl(parse_gobuster(name, text))
    return with_curl(parse_generic(name, text))


def log_paths(root: Path) -> list[Path]:
    if root.is_file():
        if root.name.startswith(".") or root.suffix.lower() in SKIP_SUFFIXES:
            return []
        return [root]
    if not root.is_dir():
        return []
    found = []
    for path in sorted(root.iterdir(), key=lambda item: item.name.lower()):
        if not path.is_file() or path.name.startswith("."):
            continue
        if path.suffix.lower() in SKIP_SUFFIXES:
            continue
        found.append(path)
    return found


def read_one(path: Path) -> dict:
    resolved = path.resolve()
    try:
        data = path.read_bytes()[:20_000_000]
        text = data.decode("utf-8", "replace")
        parsed = parse_log(path.name, text)
        parsed["size"] = path.stat().st_size
    except OSError as exc:
        parsed = empty_file(path.name, "empty", {}, [], f"Could not read this file. {exc}")
        parsed["size"] = 0
    parsed["source"] = str(resolved)
    return parsed


def scan(directory: Path, extras: list[Path] | None = None) -> dict:
    files = []
    seen: set[Path] = set()
    groups: list[tuple[Path, str]] = [(directory, "")]
    for extra in extras or []:
        groups.append((extra, str(extra)))
    for root, imported in groups:
        for path in log_paths(root):
            resolved = path.resolve()
            if resolved in seen:
                continue
            seen.add(resolved)
            parsed = read_one(path)
            parsed["imported"] = imported
            files.append(parsed)
    names: dict[str, int] = {}
    for item in files:
        names[item["name"]] = names.get(item["name"], 0) + 1
    for item in files:
        if names[item["name"]] > 1:
            item["label"] = f"{Path(item['source']).parent.name}/{item['name']}"
        else:
            item["label"] = item["name"]
    return {
        "dir": str(directory),
        "imports": [str(extra) for extra in (extras or [])],
        "files": files,
    }


def check_import(raw: str, home: Path) -> tuple[Path | None, str]:
    text = (raw or "").strip()
    if not text:
        return None, "Type a file or folder path."
    path = Path(text).expanduser()
    if not path.exists():
        return None, f"Nothing at {path}"
    path = path.resolve()
    home = home.resolve()
    if path == home:
        return None, "That folder is already the one Logburr opened."
    if path.is_file() and path.parent == home:
        return None, "That file is already in the open folder."
    if path.is_file() and (path.name.startswith(".") or path.suffix.lower() in SKIP_SUFFIXES):
        return None, "Logburr skips that file."
    if not path.is_file() and not path.is_dir():
        return None, "That path is not a file or a folder."
    return path, ""


def add_import(home: Path, extras: list[Path], lock: threading.Lock, raw: str) -> dict:
    path, message = check_import(raw, home)
    if path is None:
        return {"ok": False, "message": message}
    with lock:
        if any(item == path for item in extras):
            return {"ok": False, "message": "That path is already imported."}
        extras.append(path)
    kind = "file" if path.is_file() else "folder"
    return {"ok": True, "message": f"Imported {kind} {path}", "path": str(path)}


def remove_import(extras: list[Path], lock: threading.Lock, raw: str) -> dict:
    text = (raw or "").strip()
    if not text:
        return {"ok": False, "message": "Missing a path."}
    path = Path(text).expanduser().resolve()
    with lock:
        kept = [item for item in extras if item != path]
        if len(kept) == len(extras):
            return {"ok": False, "message": "That path is not imported."}
        extras[:] = kept
    return {"ok": True, "message": f"Removed {path}", "path": str(path)}


PAGE = r"""<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>logburr</title>
<style>
  :root {
    --bg: #0e1211;
    --bg-2: #151b19;
    --bg-3: #1c2622;
    --line: #2a3832;
    --ink: #e7f3ec;
    --muted: #8ea89a;
    --faint: #61786c;
    --green: #7dffb3;
    --blue: #8ecbff;
    --amber: #ffc46b;
    --red: #ff8d86;
    --sand: #e2d2bc;
    color-scheme: dark;
  }
  * { box-sizing: border-box; }
  html, body { margin: 0; height: 100%; }
  body {
    background: var(--bg);
    color: var(--ink);
    font: 13.5px/1.45 ui-monospace, "Cascadia Code", "JetBrains Mono", "IBM Plex Mono", monospace;
  }
  body::before {
    content: "";
    position: fixed;
    inset: 0 0 auto 0;
    height: 3px;
    background: linear-gradient(90deg, var(--green), var(--amber) 55%, var(--red));
    z-index: 5;
  }
  header {
    display: flex;
    align-items: center;
    gap: 18px;
    padding: 14px 16px 10px;
    border-bottom: 1px solid var(--line);
  }
  .brand { display: flex; gap: 10px; align-items: center; min-width: 220px; }
  .mark {
    width: 14px; height: 14px;
    background: conic-gradient(from 210deg, var(--green), var(--amber), var(--blue), var(--green));
    border-radius: 3px;
  }
  .brand strong { display: block; letter-spacing: 0.08em; font-size: 12px; }
  .brand em { display: block; color: var(--faint); font-style: normal; font-size: 11px; }
  .hint { margin-left: auto; color: var(--faint); font-size: 11px; }
  .hint b { color: var(--muted); font-weight: 600; }
  .app { display: grid; grid-template-columns: 250px 1fr; height: calc(100vh - 52px); }
  aside { border-right: 1px solid var(--line); overflow: auto; background: #101614; }
  aside h2 {
    margin: 0; padding: 12px 12px 6px;
    color: var(--faint); font-size: 10px; letter-spacing: 0.16em; font-weight: 600;
  }
  .file {
    display: grid; grid-template-columns: 1fr auto; gap: 2px 8px;
    width: 100%; text-align: left; cursor: pointer;
    background: transparent; color: inherit; border: 0;
    border-left: 2px solid transparent;
    padding: 9px 12px;
  }
  .file:hover { background: var(--bg-2); }
  .file.on { background: var(--bg-3); border-left-color: var(--green); }
  .file .nm { grid-column: 1; overflow: hidden; text-overflow: ellipsis; white-space: nowrap; }
  .file .ct { grid-column: 2; color: var(--green); }
  .file .sub {
    grid-column: 1 / -1; color: var(--faint); font-size: 11px;
    overflow: hidden; text-overflow: ellipsis; white-space: nowrap;
  }
  .file .ct.zero { color: var(--faint); }
  .import { display: flex; gap: 6px; padding: 0 12px 8px; }
  .import input { flex: 1; min-width: 0; width: auto; }
  .import button { flex: none; padding: 6px 8px; }
  .import-chip {
    display: flex; align-items: center; gap: 6px;
    margin: 0 12px 6px; color: var(--muted); font-size: 11px;
  }
  .import-chip span {
    overflow: hidden; text-overflow: ellipsis; white-space: nowrap; min-width: 0;
  }
  .import-chip button {
    flex: none; border: 0; background: transparent; color: var(--faint);
    cursor: pointer; font: inherit; padding: 0 2px;
  }
  main { display: flex; flex-direction: column; min-width: 0; }
  #meta { padding: 12px 16px 0; color: var(--muted); }
  #meta .target { color: var(--ink); }
  #meta .note { color: var(--amber); }
  details { margin-top: 6px; }
  details code {
    display: block; margin-top: 6px; color: var(--sand);
    white-space: pre-wrap; word-break: break-all;
  }
  summary { cursor: pointer; color: var(--faint); }
  .tools {
    display: flex; flex-wrap: wrap; gap: 8px; align-items: center;
    padding: 10px 16px;
  }
  input[type="search"], input[type="number"], input[type="text"] {
    background: var(--bg-2); color: var(--ink);
    border: 1px solid var(--line); border-radius: 4px;
    padding: 6px 8px; font: inherit;
  }
  input[type="search"] { width: min(420px, 46vw); }
  input[type="search"]:focus, input[type="number"]:focus, input[type="text"]:focus { outline: 1px solid var(--green); border-color: transparent; }
  input[type="number"] { width: 58px; }
  .editor { padding: 0 16px 8px; }
  .editor[hidden] { display: none; }
  .editor textarea {
    width: 100%; min-height: 7.2em; max-height: 16em; resize: vertical;
    background: #101614; color: var(--sand);
    border: 1px solid var(--line); border-radius: 6px;
    padding: 8px 10px; font: inherit; white-space: pre;
  }
  .editor textarea:focus { outline: 1px solid var(--green); border-color: transparent; }
  button, .chip {
    background: var(--bg-2); color: var(--ink);
    border: 1px solid var(--line); border-radius: 999px;
    padding: 5px 10px; font: inherit; cursor: pointer;
  }
  button:hover, .chip:hover { border-color: var(--muted); }
  button.on, .chip.on { background: #163028; border-color: #2f6b4a; color: var(--green); }
  button.ghost { border-radius: 4px; }
  .hide { display: flex; align-items: center; gap: 6px; color: var(--muted); }
  #count { color: var(--faint); margin-left: auto; }
  #prefixes, #buckets { display: flex; flex-wrap: wrap; gap: 6px; padding: 0 16px 8px; }
  .chip small { color: var(--faint); margin-left: 6px; }
  .chip.on small, .chip:hover small { color: inherit; }
  .bucket { text-align: left; border-radius: 6px; padding: 6px 8px 7px; min-width: 140px; }
  .bucket .top { display: flex; justify-content: space-between; gap: 10px; }
  .bucket .blurb { display: block; color: var(--faint); font-size: 10px; margin-top: 2px; letter-spacing: 0.02em; }
  .bucket .tags { display: flex; flex-wrap: wrap; gap: 4px; margin-top: 6px; }
  .bucket .tags i {
    font-style: normal; font-size: 10px; color: var(--ink);
    background: #101614; border: 1px solid var(--line); border-radius: 999px;
    padding: 1px 6px; max-width: 16ch; overflow: hidden; text-overflow: ellipsis;
  }
  .bucket .tags i:hover { border-color: var(--green); color: var(--green); }
  .bucket .share { display: block; height: 3px; margin-top: 6px; background: #24302b; border-radius: 2px; }
  .bucket .share i { display: block; height: 100%; width: var(--p); background: currentColor; border-radius: 2px; }
  .bucket.dim { opacity: 0.45; }
  .bucket.dim.on, .bucket.on { opacity: 1; }
  .pill {
    display: inline-block; min-width: 2.6em; text-align: center;
    padding: 1px 6px; border-radius: 999px; font-weight: 700;
  }
  .s2 { color: var(--green); background: #143226; }
  .s3 { color: var(--blue); background: #132838; }
  .auth { color: var(--amber); background: #332816; }
  .method { color: var(--sand); background: #2c2822; }
  .miss { color: #9aaba3; background: #222826; }
  .s4 { color: #ffb088; background: #332016; }
  .s5 { color: var(--red); background: #351918; }
  .s0 { color: var(--muted); background: var(--bg-3); }
  .scroller { overflow: auto; flex: 1; }
  button:disabled { opacity: 0.45; cursor: wait; }
  .output {
    display: flex; flex-direction: column; flex: 0 1 42%; min-height: 0;
    border-top: 1px solid var(--line); background: #101614;
  }
  .output[hidden] { display: none; }
  .output.collapsed { flex: none; }
  .output.collapsed pre { display: none; }
  .output-bar {
    display: flex; align-items: center; gap: 8px; flex: none;
    padding: 6px 12px; border-bottom: 1px solid var(--line);
  }
  .output.collapsed .output-bar { border-bottom: 0; }
  .output-bar span {
    color: var(--muted); overflow: hidden; text-overflow: ellipsis;
    white-space: nowrap; min-width: 0;
  }
  #output-name { width: 220px; margin-left: auto; flex: none; }
  .output pre {
    margin: 0; padding: 10px 14px 16px; overflow: auto; flex: 1; min-height: 0;
    color: var(--sand); white-space: pre-wrap; word-break: break-word;
  }
  .hl-status { color: var(--green); font-weight: 700; }
  .hl-h { color: var(--blue); }
  .hl-key { color: var(--amber); }
  .hl-str { color: var(--green); }
  .hl-num { color: #8ecbff; }
  .hl-lit { color: var(--red); }
  .hl-punct { color: var(--faint); }
  table { width: 100%; border-collapse: collapse; }
  th {
    position: sticky; top: 0; z-index: 1;
    background: #121816; text-align: left; font-weight: 600;
    color: var(--faint); font-size: 10px; letter-spacing: 0.12em;
    padding: 8px 10px; border-bottom: 1px solid var(--line); cursor: pointer;
    white-space: nowrap;
  }
  th .arrow { color: var(--green); }
  td { padding: 6px 10px; border-bottom: 1px solid #1d2824; white-space: nowrap; vertical-align: baseline; }
  tr.hit { cursor: pointer; }
  tr.hit:hover td { background: #16211c; }
  tr.hit.sel td { background: #1a2c24; }
  td.path { max-width: 1px; width: 40%; overflow: hidden; text-overflow: ellipsis; color: var(--ink); }
  td.payload {
    color: var(--sand); font-size: 12px; max-width: 26ch;
    overflow: hidden; text-overflow: ellipsis;
  }
  td.num { text-align: right; color: var(--muted); font-variant-numeric: tabular-nums; }
  td.time { color: var(--muted); min-width: 72px; }
  td.time i.bar {
    display: block; height: 2px; margin-top: 3px; width: var(--w); background: var(--amber); border-radius: 2px;
  }
  mark { background: #3a3416; color: var(--amber); padding: 0 1px; }
  tr.detail td { background: #101816; color: var(--sand); white-space: normal; }
  .facts { display: grid; grid-template-columns: 5.5em minmax(0, 1fr); gap: 3px 14px; padding: 4px 0; font-size: 12px; }
  .facts b { color: var(--faint); font-weight: 600; letter-spacing: 0.08em; font-size: 10px; }
  .facts span { word-break: break-all; }
  .empty {
    margin: 28px 16px; color: var(--muted);
    border: 1px dashed var(--line); padding: 22px; border-radius: 8px;
  }
  pre.preview {
    margin: 0 16px 16px; padding: 12px; overflow: auto;
    background: var(--bg-2); color: var(--sand); border-radius: 6px;
    max-height: 360px;
  }
  #toast {
    position: fixed; right: 16px; bottom: 16px;
    background: var(--green); color: #062116; font-weight: 700;
    padding: 8px 12px; border-radius: 4px;
    opacity: 0; transform: translateY(8px); pointer-events: none;
    transition: opacity .15s, transform .15s;
  }
  #toast.on { opacity: 1; transform: none; }
</style>
</head>
<body>
<header>
  <div class="brand"><span class="mark"></span><div><strong>LOGBURR</strong><em id="where">loading logs…</em></div></div>
  <div class="hint"><b>/</b> search &nbsp; <b>j</b><b>k</b> move &nbsp; <b>enter</b> raw &nbsp; <b>c</b> url &nbsp; <b>x</b> curl &nbsp; <b>b</b> burp &nbsp; <b>r</b> run &nbsp; <b>h</b> repeats</div>
</header>
<div class="app">
  <aside>
    <h2>LOGS</h2>
    <form id="import-form" class="import">
      <input id="import-path" type="text" spellcheck="false" autocomplete="off" placeholder="File or folder path">
      <button type="submit">Import</button>
    </form>
    <div id="import-list"></div>
    <div id="files"></div>
  </aside>
  <main>
    <div id="meta"></div>
    <div class="tools">
      <input id="q" type="search" placeholder="Filter path, url, type, status…" autocomplete="off" spellcheck="false">
      <span id="classes"></span>
      <label class="hide"><input id="hide" type="checkbox" checked> Hide groups of</label>
      <input id="threshold" type="number" min="2" max="9999" value="5">
      <button class="ghost" id="copy" type="button">Copy URLs</button>
      <button class="ghost" id="curl" type="button">Copy cURL</button>
      <button class="ghost" id="burp" type="button" title="Send the selected request through 127.0.0.1:8080">Send to Burp</button>
      <button class="ghost" id="run" type="button" title="Run the request directly and show the response">Run</button>
      <label class="hide" title="Change the request before Run, Burp, or Copy cURL. Untick to restore the row."><input id="edit-request" type="checkbox"> Edit</label>
      <button class="ghost" id="reload" type="button">Refresh</button>
      <button class="ghost" id="reset" type="button">Reset</button>
      <span id="count"></span>
    </div>
    <section id="editor" class="editor" hidden>
      <textarea id="editor-text" spellcheck="false" autocomplete="off" placeholder="POST https://host/path"></textarea>
    </section>
    <div id="prefixes"></div>
    <div id="buckets"></div>
    <div class="scroller" id="scroller"></div>
    <section id="output" class="output" hidden>
      <div class="output-bar">
        <button class="ghost" id="output-toggle" type="button">Hide response</button>
        <span id="output-meta"></span>
        <input id="output-name" type="text" spellcheck="false" autocomplete="off" placeholder="name.http">
        <button class="ghost" id="output-save" type="button">Save</button>
      </div>
      <pre id="output-view"></pre>
    </section>
  </main>
</div>
<div id="toast"></div>
<script>
const state = {
  scan: null,
  active: 0,
  q: "",
  classes: {1: true, 2: true, 3: true, 4: true, 5: true},
  hide: true,
  threshold: 5,
  only: null,
  prefix: null,
  sort: "rare",
  dir: "asc",
  cursor: 0,
  editKey: "",
  cursorKey: "",
  openKey: "",
  keyboard: false,
  outputText: "",
};

const $ = (id) => document.getElementById(id);
const filesEl = $("files");
const metaEl = $("meta");
const classEl = $("classes");
const prefixEl = $("prefixes");
const bucketEl = $("buckets");
const scroller = $("scroller");
const qEl = $("q");

function tone(code) {
  if (code === 401 || code === 403) return "auth";
  if (code === 404) return "miss";
  if (code === 405) return "method";
  if (code >= 200 && code < 300) return "s2";
  if (code >= 300 && code < 400) return "s3";
  if (code >= 400 && code < 500) return "s4";
  if (code >= 500 && code < 600) return "s5";
  return "s0";
}
function klass(code) { return Math.floor(Number(code) / 100); }
function sigKey(row) {
  return [row.status, row.bytes ?? "", row.words ?? "", row.lines ?? "", row.ctype || ""].join("|");
}
function rowKey(row) { return sigKey(row) + "|" + (row.url || row.path) + "|" + (row.raw || ""); }
function basename(path) {
  if (!path) return "";
  const parts = String(path).split(/[\\/]/);
  return parts[parts.length - 1];
}
function prefixOf(path) {
  const parts = String(path || "").split("?")[0].split("/").filter(Boolean);
  if (!parts.length) return "/";
  if (parts[0] === "api" && /^v\d+$/.test(parts[1] || "")) return "/api/" + parts[1];
  return "/" + parts[0];
}
function sigText(sig) {
  const bits = [];
  if (sig.bytes != null) bits.push(sig.bytes + " B");
  if (sig.words != null) bits.push(sig.words + " w");
  if (sig.lines != null) bits.push(sig.lines + " l");
  if (sig.ctype) bits.push(sig.ctype.split(";")[0].replace("application/", "").replace("text/", ""));
  return bits.join(" · ") || "no size";
}
function blurb(sig, total) {
  if (sig.count < 5 || total < 1) return "";
  const share = sig.count / total;
  if (share < 0.12) return "";
  if (sig.status === 200 && sig.ctype && sig.ctype.indexOf("html") !== -1) return "same body · likely wildcard";
  if (sig.status === 405) return "method not allowed";
  if (sig.status === 404) return "not found";
  if (sig.status === 403) return "forbidden";
  if (sig.status === 401) return "unauthorized";
  if (share >= 0.4) return "repeated response";
  return "";
}
function formatMs(ms) {
  if (ms == null) return "";
  if (ms >= 1000) return (ms / 1000).toFixed(2) + " s";
  return Math.round(ms) + " ms";
}
function fillHighlight(el, text, query) {
  el.textContent = "";
  const value = text == null ? "" : String(text);
  if (!query) { el.textContent = value; return; }
  const lower = value.toLowerCase();
  const needle = query.toLowerCase();
  let index = 0;
  while (index < value.length) {
    const found = lower.indexOf(needle, index);
    if (found < 0) {
      el.appendChild(document.createTextNode(value.slice(index)));
      break;
    }
    if (found > index) el.appendChild(document.createTextNode(value.slice(index, found)));
    const mark = document.createElement("mark");
    mark.textContent = value.slice(found, found + needle.length);
    el.appendChild(mark);
    index = found + needle.length;
  }
}
function toast(message) {
  const el = $("toast");
  el.textContent = message;
  el.classList.add("on");
  clearTimeout(toast._t);
  toast._t = setTimeout(() => el.classList.remove("on"), 1400);
}
function activeFile() {
  if (!state.scan || !state.scan.files.length) return null;
  return state.scan.files[state.active] || state.scan.files[0];
}
function signatures(rows) {
  const map = new Map();
  for (const row of rows) {
    const key = sigKey(row);
    let sig = map.get(key);
    if (!sig) {
      sig = {
        key, status: row.status, bytes: row.bytes, words: row.words,
        lines: row.lines, ctype: row.ctype, count: 0, samples: [],
      };
      map.set(key, sig);
    }
    sig.count += 1;
    const sample = row.fuzz || row.path || "";
    if (sample && sig.samples.length < 3 && sig.samples.indexOf(sample) === -1) sig.samples.push(sample);
  }
  return map;
}
function matchesQuery(row, query) {
  if (!query) return true;
  const hay = [row.status, row.method, row.path, row.payload, row.url, row.redirect, row.ctype, row.raw]
    .join(" ").toLowerCase();
  return hay.indexOf(query) !== -1;
}
function viewModel() {
  const file = activeFile();
  if (!file) return null;
  const sigs = signatures(file.rows);
  const query = state.q.trim().toLowerCase();
  const searched = file.rows.filter((row) => state.classes[klass(row.status)] !== false && matchesQuery(row, query));
  const hiddenByRepeat = (row) => {
    if (!state.hide) return false;
    if (state.only && state.only === sigKey(row)) return false;
    return (sigs.get(sigKey(row)) || {count: 1}).count >= state.threshold;
  };
  const prefixSource = searched.filter((row) => {
    if (state.only && state.only !== "singles" && sigKey(row) !== state.only) return false;
    if (state.only === "singles" && (sigs.get(sigKey(row)) || {count: 1}).count !== 1) return false;
    return !hiddenByRepeat(row);
  });
  let rows = prefixSource.filter((row) => !state.prefix || prefixOf(row.path) === state.prefix);
  const compare = {
    rare: (a, b) => (sigs.get(sigKey(a)).count - sigs.get(sigKey(b)).count) || a.status - b.status || String(a.path).localeCompare(String(b.path)),
    status: (a, b) => a.status - b.status || (a.bytes || 0) - (b.bytes || 0) || String(a.path).localeCompare(String(b.path)),
    bytes: (a, b) => (a.bytes ?? -1) - (b.bytes ?? -1) || String(a.path).localeCompare(String(b.path)),
    words: (a, b) => (a.words ?? -1) - (b.words ?? -1),
    ms: (a, b) => (a.ms ?? -1) - (b.ms ?? -1),
    path: (a, b) => String(a.path).localeCompare(String(b.path)),
    payload: (a, b) => String(a.payload || "").localeCompare(String(b.payload || "")),
  }[state.sort];
  rows = rows.slice().sort((a, b) => {
    const delta = compare(a, b);
    return state.dir === "desc" ? -delta : delta;
  });
  return { file, sigs, rows, searched, prefixSource };
}

function renderFiles() {
  filesEl.textContent = "";
  const list = state.scan.files;
  if (!list.length) {
    const p = document.createElement("p");
    p.className = "empty";
    p.textContent = "No logs yet. Import a file or folder above.";
    filesEl.appendChild(p);
    return;
  }
  list.forEach((file, index) => {
    const button = document.createElement("button");
    button.type = "button";
    button.className = "file" + (index === state.active ? " on" : "");
    const name = document.createElement("span");
    name.className = "nm";
    name.textContent = file.label || file.name;
    name.title = file.source || file.name;
    const count = document.createElement("span");
    count.className = "ct" + (file.rows.length ? "" : " zero");
    count.textContent = file.rows.length ? String(file.rows.length) : "0";
    const sub = document.createElement("span");
    sub.className = "sub";
    const bits = [];
    if (file.imported) bits.push(file.source);
    bits.push(file.tool + (file.meta && file.meta.target ? "  ·  " + file.meta.target : ""));
    sub.textContent = bits.filter(Boolean).join("  ·  ");
    sub.title = sub.textContent;
    button.append(name, count, sub);
    button.addEventListener("click", () => {
      state.active = index;
      state.only = null;
      state.prefix = null;
      state.cursor = 0;
      state.openKey = "";
      render();
    });
    filesEl.appendChild(button);
  });
}

function renderMeta(model) {
  metaEl.textContent = "";
  const file = model.file;
  const meta = file.meta || {};
  const line = document.createElement("div");
  const tool = document.createElement("b");
  tool.textContent = file.tool;
  line.appendChild(tool);
  if (meta.target) {
    line.appendChild(document.createTextNode("   "));
    const target = document.createElement("span");
    target.className = "target";
    target.textContent = meta.target;
    line.appendChild(target);
  }
  const bits = [];
  if (meta.wordlist) bits.push(basename(meta.wordlist));
  if (meta.method) bits.push(meta.method);
  if (meta.depth) bits.push("depth " + meta.depth);
  if (meta.time) bits.push(meta.time);
  if (bits.length) line.appendChild(document.createTextNode("   ·   " + bits.join("   ·   ")));
  metaEl.appendChild(line);
  if (file.note) {
    const note = document.createElement("div");
    note.className = "note";
    note.textContent = file.note;
    metaEl.appendChild(note);
  }
  if (meta.command) {
    const details = document.createElement("details");
    const summary = document.createElement("summary");
    summary.textContent = "command";
    const code = document.createElement("code");
    code.textContent = meta.command;
    details.append(summary, code);
    metaEl.appendChild(details);
  }
  if (meta.wordlist) {
    const details = document.createElement("details");
    const summary = document.createElement("summary");
    summary.textContent = "wordlist";
    const code = document.createElement("code");
    code.textContent = meta.wordlist;
    details.append(summary, code);
    metaEl.appendChild(details);
  }
}

function renderClasses(model) {
  classEl.textContent = "";
  const counts = {};
  for (const row of model.file.rows) {
    const key = klass(row.status);
    counts[key] = (counts[key] || 0) + 1;
  }
  Object.keys(counts).sort().forEach((key) => {
    const button = document.createElement("button");
    button.type = "button";
    button.className = state.classes[key] === false ? "" : "on";
    button.textContent = key + "xx  " + counts[key];
    button.addEventListener("click", () => {
      state.classes[key] = state.classes[key] === false;
      render();
    });
    classEl.appendChild(button);
  });
}

function renderPrefixes(model) {
  prefixEl.textContent = "";
  const counts = new Map();
  for (const row of model.prefixSource) {
    const key = prefixOf(row.path);
    counts.set(key, (counts.get(key) || 0) + 1);
  }
  const entries = Array.from(counts.entries()).sort((a, b) => b[1] - a[1] || a[0].localeCompare(b[0]));
  if (entries.length < 2) return;
  entries.slice(0, 28).forEach(([key, count]) => {
    const button = document.createElement("button");
    button.type = "button";
    button.className = "chip" + (state.prefix === key ? " on" : "");
    button.textContent = key + "  " + count;
    button.addEventListener("click", () => {
      state.prefix = state.prefix === key ? null : key;
      state.cursor = 0;
      render();
    });
    prefixEl.appendChild(button);
  });
}

function renderBuckets(model) {
  bucketEl.textContent = "";
  const sigs = Array.from(model.sigs.values());
  const clumps = sigs.filter((sig) => sig.count >= 2).sort((a, b) => b.count - a.count || a.status - b.status);
  const singles = sigs.filter((sig) => sig.count === 1);
  const total = model.file.rows.length || 1;
  const shown = clumps.slice(0, 14);
  if (!shown.length && singles.length < 2) return;
  shown.forEach((sig) => {
    const hidden = state.hide && sig.count >= state.threshold && state.only !== sig.key;
    const button = document.createElement("button");
    button.type = "button";
    button.className = "bucket " + tone(sig.status) + (hidden ? " dim" : "") + (state.only === sig.key ? " on" : "");
    const top = document.createElement("span");
    top.className = "top";
    const pill = document.createElement("span");
    pill.className = "pill " + tone(sig.status);
    pill.textContent = String(sig.status);
    const count = document.createElement("b");
    count.textContent = "×" + sig.count;
    top.append(pill, count);
    const text = document.createElement("span");
    text.textContent = sigText(sig);
    button.append(top, text);
    const why = blurb(sig, total);
    if (why) {
      const small = document.createElement("span");
      small.className = "blurb";
      small.textContent = why;
      button.appendChild(small);
    }
    if (sig.samples.length) {
      const tags = document.createElement("span");
      tags.className = "tags";
      sig.samples.forEach((sample) => {
        const tag = document.createElement("i");
        tag.textContent = sample;
        tag.title = "Show " + sample;
        tag.addEventListener("click", (event) => {
          event.stopPropagation();
          state.q = sample;
          qEl.value = sample;
          state.only = sig.key;
          state.prefix = null;
          state.cursor = 0;
          render();
        });
        tags.appendChild(tag);
      });
      button.appendChild(tags);
    }
    const share = document.createElement("span");
    share.className = "share";
    const bar = document.createElement("i");
    bar.style.setProperty("--p", Math.max(4, Math.round((sig.count / total) * 100)) + "%");
    share.appendChild(bar);
    button.appendChild(share);
    button.addEventListener("click", () => {
      state.only = state.only === sig.key ? null : sig.key;
      state.cursor = 0;
      render();
    });
    bucketEl.appendChild(button);
  });
  if (singles.length) {
    const button = document.createElement("button");
    button.type = "button";
    button.className = "chip" + (state.only === "singles" ? " on" : "");
    button.textContent = "unique  " + singles.length;
    button.addEventListener("click", () => {
      state.only = state.only === "singles" ? null : "singles";
      state.cursor = 0;
      render();
    });
    bucketEl.appendChild(button);
  }
}

function columnOn(rows, field) {
  return rows.some((row) => row[field] != null && row[field] !== "");
}

function renderTable(model) {
  scroller.textContent = "";
  const rows = model.rows;
  if (!model.file.rows.length) {
    if (model.file.preview) {
      const pre = document.createElement("pre");
      pre.className = "preview";
      pre.textContent = model.file.preview;
      scroller.appendChild(pre);
    } else {
      const p = document.createElement("p");
      p.className = "empty";
      p.textContent = model.file.note || "No hits in this log.";
      scroller.appendChild(p);
    }
    $("count").textContent = "0 hits";
    return;
  }
  if (!rows.length) {
    const p = document.createElement("p");
    p.className = "empty";
    p.textContent = "Nothing matches these filters. Reset, or click a dimmed group to look inside it.";
    scroller.appendChild(p);
    $("count").textContent = "0 of " + model.file.rows.length;
    return;
  }
  const idx = rows.findIndex((row) => rowKey(row) === state.cursorKey);
  state.cursor = idx >= 0 ? idx : Math.min(state.cursor, rows.length - 1);
  state.cursorKey = rowKey(rows[state.cursor]);

  const showBytes = columnOn(model.file.rows, "bytes");
  const showWords = columnOn(model.file.rows, "words");
  const showLines = columnOn(model.file.rows, "lines");
  const showType = columnOn(model.file.rows, "ctype");
  const showRedir = columnOn(model.file.rows, "redirect");
  const showTime = columnOn(model.file.rows, "ms");
  const showPayload = model.file.rows.some((row) => row.payload && row.payload !== row.path);
  const maxMs = showTime ? Math.max(...model.file.rows.map((row) => row.ms || 0)) : 0;
  const columns = [
    ["status", "STATUS"],
    ["method", "METHOD"],
  ];
  if (showBytes) columns.push(["bytes", "SIZE"]);
  if (showWords) columns.push(["words", "WORDS"]);
  if (showLines) columns.push(["lines", "LINES"]);
  if (showType) columns.push(["type", "TYPE"]);
  if (showTime) columns.push(["ms", "TIME"]);
  if (showPayload) columns.push(["payload", "PAYLOAD"]);
  columns.push(["path", "PATH"]);
  if (showRedir) columns.push(["redirect", "REDIRECT"]);

  const table = document.createElement("table");
  const thead = document.createElement("thead");
  const head = document.createElement("tr");
  columns.forEach(([key, label]) => {
    const th = document.createElement("th");
    th.textContent = label;
    if (state.sort === key) {
      const arrow = document.createElement("span");
      arrow.className = "arrow";
      arrow.textContent = state.dir === "asc" ? "  ▲" : "  ▼";
      th.appendChild(arrow);
    }
    if (key !== "method" && key !== "type" && key !== "lines" && key !== "redirect") {
      th.addEventListener("click", () => {
        if (state.sort === key) state.dir = state.dir === "asc" ? "desc" : "asc";
        else { state.sort = key; state.dir = key === "ms" || key === "bytes" ? "desc" : "asc"; }
        render();
      });
    }
    head.appendChild(th);
  });
  thead.appendChild(head);
  table.appendChild(thead);
  const body = document.createElement("tbody");
  let selectedRow = null;
  rows.forEach((row, index) => {
    const tr = document.createElement("tr");
    tr.className = "hit" + (index === state.cursor ? " sel" : "");
    if (index === state.cursor) selectedRow = tr;
    const status = document.createElement("td");
    const pill = document.createElement("span");
    pill.className = "pill " + tone(row.status);
    pill.textContent = String(row.status);
    status.appendChild(pill);
    const method = document.createElement("td");
    method.textContent = row.method || "";
    tr.append(status, method);
    if (showBytes) {
      const td = document.createElement("td");
      td.className = "num";
      td.textContent = row.bytes == null ? "" : row.bytes + " B";
      tr.appendChild(td);
    }
    if (showWords) {
      const td = document.createElement("td");
      td.className = "num";
      td.textContent = row.words == null ? "" : String(row.words);
      tr.appendChild(td);
    }
    if (showLines) {
      const td = document.createElement("td");
      td.className = "num";
      td.textContent = row.lines == null ? "" : String(row.lines);
      tr.appendChild(td);
    }
    if (showType) {
      const td = document.createElement("td");
      const short = (row.ctype || "").split(";")[0].replace("application/", "").replace("text/", "");
      td.textContent = short;
      td.title = row.ctype || "";
      tr.appendChild(td);
    }
    if (showTime) {
      const td = document.createElement("td");
      td.className = "time";
      td.textContent = formatMs(row.ms);
      if (row.ms && maxMs) {
        const bar = document.createElement("i");
        bar.className = "bar";
        bar.style.setProperty("--w", Math.max(4, Math.round((row.ms / maxMs) * 100)) + "%");
        td.appendChild(bar);
      }
      tr.appendChild(td);
    }
    if (showPayload) {
      const td = document.createElement("td");
      td.className = "payload";
      fillHighlight(td, row.payload || "", state.q.trim());
      td.title = row.payload || "";
      tr.appendChild(td);
    }
    const path = document.createElement("td");
    path.className = "path";
    fillHighlight(path, row.path || row.url, state.q.trim());
    path.title = row.url || row.path || "";
    tr.appendChild(path);
    if (showRedir) {
      const td = document.createElement("td");
      td.className = "path";
      td.textContent = row.redirect || "";
      td.title = row.redirect || "";
      tr.appendChild(td);
    }
    tr.addEventListener("click", () => {
      state.cursor = index;
      state.cursorKey = rowKey(row);
      state.openKey = state.openKey === rowKey(row) ? "" : rowKey(row);
      state.keyboard = false;
      render();
    });
    body.appendChild(tr);
    if (state.openKey && state.openKey === rowKey(row)) {
      const detail = document.createElement("tr");
      detail.className = "detail";
      const td = document.createElement("td");
      td.colSpan = columns.length;
      const facts = document.createElement("div");
      facts.className = "facts";
      const addFact = (label, value) => {
        if (value == null || value === "") return;
        const name = document.createElement("b");
        name.textContent = label;
        const val = document.createElement("span");
        val.textContent = String(value);
        facts.append(name, val);
      };
      addFact("curl", row.curl);
      addFact("payload", row.payload);
      addFact("url", row.url || row.path);
      addFact("fuzz", row.fuzz);
      addFact("redirect", row.redirect);
      addFact("position", row.position);
      addFact("status", row.status);
      addFact("size", row.bytes == null ? "" : row.bytes + " B");
      addFact("words", row.words);
      addFact("lines", row.lines);
      addFact("type", row.ctype);
      addFact("time", formatMs(row.ms));
      addFact("hash", row.hash);
      td.appendChild(facts);
      detail.appendChild(td);
      body.appendChild(detail);
    }
  });
  table.appendChild(body);
  scroller.appendChild(table);
  const hidden = model.file.rows.length - rows.length;
  $("count").textContent = rows.length + " shown" + (hidden ? "  ·  " + hidden + " hidden" : "") + "  ·  " + model.file.rows.length + " hits";
  if (state.keyboard && selectedRow) selectedRow.scrollIntoView({ block: "nearest" });
}

function renderImports() {
  const box = $("import-list");
  box.textContent = "";
  (state.scan.imports || []).forEach((path) => {
    const row = document.createElement("div");
    row.className = "import-chip";
    const span = document.createElement("span");
    span.textContent = path;
    span.title = path;
    const drop = document.createElement("button");
    drop.type = "button";
    drop.textContent = "×";
    drop.title = "Remove this import";
    drop.addEventListener("click", () => removeImport(path));
    row.append(span, drop);
    box.appendChild(row);
  });
}
function render() {
  if (!state.scan) return;
  $("where").textContent = state.scan.dir;
  renderImports();
  renderFiles();
  const model = viewModel();
  if (!model) {
    metaEl.textContent = "";
    scroller.textContent = "";
    const p = document.createElement("p");
    p.className = "empty";
    p.textContent = "Import a log file or a folder, or drop logs in the folder Logburr opened.";
    scroller.appendChild(p);
    return;
  }
  renderMeta(model);
  renderClasses(model);
  renderPrefixes(model);
  renderBuckets(model);
  renderTable(model);
  if ($("edit-request").checked) loadEditor(false);
}

async function load(keepSource) {
  const response = await fetch("/api/scan", { cache: "no-store" });
  if (!response.ok) throw new Error("scan failed");
  state.scan = await response.json();
  if (keepSource) {
    const index = state.scan.files.findIndex((file) => file.source === keepSource || file.name === keepSource);
    if (index >= 0) state.active = index;
  } else if (state.scan.files.length) {
    let best = 0;
    state.scan.files.forEach((file, index) => {
      if (file.rows.length > state.scan.files[best].rows.length) best = index;
    });
    state.active = best;
  }
  if (state.active >= state.scan.files.length) state.active = 0;
  render();
}

function visibleUrls() {
  const model = viewModel();
  if (!model) return [];
  return model.rows.map((row) => row.url || row.path).filter(Boolean);
}
async function copyText(text, message) {
  try {
    await navigator.clipboard.writeText(text);
  } catch (err) {
    const area = document.createElement("textarea");
    area.value = text;
    document.body.appendChild(area);
    area.select();
    document.execCommand("copy");
    area.remove();
  }
  toast(message);
}

qEl.addEventListener("input", () => {
  state.q = qEl.value;
  state.cursor = 0;
  render();
});
$("hide").addEventListener("change", () => {
  state.hide = $("hide").checked;
  render();
});
function setThreshold() {
  const value = Number($("threshold").value);
  if (!Number.isFinite(value) || value < 2) return;
  state.threshold = value;
  render();
}
$("threshold").addEventListener("change", setThreshold);
$("threshold").addEventListener("input", setThreshold);
$("copy").addEventListener("click", () => {
  const urls = visibleUrls();
  if (!urls.length) { toast("Nothing to copy"); return; }
  copyText(urls.join("\n"), "Copied " + urls.length + " URL" + (urls.length === 1 ? "" : "s"));
});
function selectedRow() {
  const model = viewModel();
  if (!model || !model.rows.length) return null;
  return model.rows[Math.min(state.cursor, model.rows.length - 1)] || null;
}
function copyCurl() {
  if ($("edit-request").checked) {
    const req = requestForSend();
    if (!req) { toast("Select a row first"); return; }
    if (req.error) { toast(req.error); return; }
    copyText(buildCurl(req), "Copied cURL  " + (req.label || req.url));
    return;
  }
  const row = selectedRow();
  if (!row || !row.curl) { toast("Select a row first"); return; }
  copyText(row.curl, "Copied cURL  " + (row.payload || row.path || row.url));
}
$("curl").addEventListener("click", copyCurl);
function selectedRequest() {
  const row = selectedRow();
  const file = activeFile();
  if (!row || !row.url) return null;
  const fuzz = row.fuzz || "";
  const templates = (file && file.meta && file.meta.headers) || [];
  return {
    url: row.url,
    method: row.method || (file && file.meta && file.meta.method) || "GET",
    headers: templates.map((header) => String(header).split("FUZZ").join(fuzz)),
    body: row.payload || "",
    label: row.payload || row.path || row.url,
    name: suggestName(row)
  };
}
function suggestName(row) {
  const raw = String(row.fuzz || row.path || "response")
    .replace(/[^A-Za-z0-9._-]+/g, "_")
    .replace(/^_+|_+$/g, "")
    .slice(0, 40);
  return (raw || "response") + ".http";
}
function requestText(req) {
  const lines = [req.method + " " + req.url].concat(req.headers || []);
  return req.body ? lines.join("\n") + "\n\n" + req.body : lines.join("\n");
}
function parseEditor(text) {
  const raw = String(text || "").replace(/\r\n/g, "\n").replace(/\r/g, "\n");
  const split = raw.indexOf("\n\n");
  const head = (split < 0 ? raw : raw.slice(0, split)).replace(/\n$/, "");
  const body = split < 0 ? "" : raw.slice(split + 2);
  const lines = head.split("\n").filter((line) => line.trim());
  if (!lines.length) return null;
  const parts = lines[0].trim().split(/\s+/);
  const url = parts.slice(1).join(" ");
  if (parts.length < 2 || !/^https?:\/\//i.test(url)) return null;
  const headers = [];
  for (const line of lines.slice(1)) {
    if (!line.includes(":")) return null;
    headers.push(line.trim());
  }
  return {
    method: parts[0].toUpperCase(),
    url,
    headers,
    body,
    label: body.trim() || url
  };
}
function shellSingle(value) {
  return "'" + String(value).replace(/'/g, "'\\''") + "'";
}
function buildCurl(req) {
  if (!req || !req.url) return "";
  const parts = ["curl"];
  if (req.url.toLowerCase().startsWith("https://")) parts.push("-k");
  if (req.method && req.method.toUpperCase() !== "GET") parts.push("-X", req.method.toUpperCase());
  parts.push(shellSingle(req.url));
  (req.headers || []).forEach((header) => {
    if (header) parts.push("-H", shellSingle(header));
  });
  if (req.body) parts.push("-d", shellSingle(req.body));
  return parts.join(" ");
}
function loadEditor(force) {
  const req = selectedRequest();
  const box = $("editor-text");
  if (!req) {
    box.value = "";
    state.editKey = "";
    return;
  }
  const key = rowKey(selectedRow());
  if (!force && state.editKey === key) return;
  state.editKey = key;
  box.value = requestText(req);
}
function resetEditor() {
  state.editKey = "";
  $("editor-text").value = "";
  $("editor").hidden = true;
  $("edit-request").checked = false;
}
function requestForSend() {
  const base = selectedRequest();
  if (!$("edit-request").checked) return base;
  const parsed = parseEditor($("editor-text").value);
  if (!parsed) return { error: "First line should look like: POST https://host/path" };
  if (base) parsed.name = base.name;
  else parsed.name = suggestName({ path: parsed.url });
  return parsed;
}
$("edit-request").addEventListener("change", () => {
  const on = $("edit-request").checked;
  $("editor").hidden = !on;
  if (on) loadEditor(true);
  else resetEditor();
});
async function sendToBurp() {
  const req = requestForSend();
  if (!req) { toast("Select a row first"); return; }
  if (req.error) { toast(req.error); return; }
  const button = $("burp");
  button.disabled = true;
  try {
    const response = await fetch("/api/burp", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({
        url: req.url,
        method: req.method,
        headers: req.headers,
        body: req.body
      })
    });
    const data = await response.json();
    toast(data.message || (data.ok ? "Sent to Burp" : "Burp did not accept it"));
  } catch (err) {
    toast("Could not reach the viewer");
  } finally {
    button.disabled = false;
  }
}
$("burp").addEventListener("click", sendToBurp);
function formatResponse(raw) {
  const text = String(raw || "").replace(/\r\n/g, "\n").replace(/\r/g, "\n");
  const split = text.indexOf("\n\n");
  if (split < 0) return text;
  const head = text.slice(0, split);
  let body = text.slice(split + 2);
  const trimmed = body.trim();
  const jsonLike = (trimmed.startsWith("{") || trimmed.startsWith("["))
    && (trimmed.endsWith("}") || trimmed.endsWith("]"));
  if (jsonLike) {
    try {
      body = JSON.stringify(JSON.parse(trimmed), null, 2);
      if (text.endsWith("\n")) body += "\n";
    } catch (err) { /* keep the body as curl printed it */ }
  }
  return head + "\n\n" + body;
}
function paintOutput(raw) {
  const formatted = formatResponse(raw);
  state.outputText = formatted;
  const view = $("output-view");
  view.replaceChildren();
  const split = formatted.indexOf("\n\n");
  const head = split < 0 ? formatted : formatted.slice(0, split);
  const body = split < 0 ? "" : formatted.slice(split + 2);
  head.split("\n").forEach((line, index) => {
    if (index) view.appendChild(document.createTextNode("\n"));
    if (index === 0) {
      view.appendChild(highlightSpan("hl-status", line));
      return;
    }
    const colon = line.indexOf(":");
    if (colon > 0) {
      view.appendChild(highlightSpan("hl-h", line.slice(0, colon)));
      view.appendChild(document.createTextNode(line.slice(colon)));
    } else {
      view.appendChild(document.createTextNode(line));
    }
  });
  if (!body) return;
  view.appendChild(document.createTextNode("\n\n"));
  const trimmed = body.trim();
  if (trimmed.startsWith("{") || trimmed.startsWith("[")) paintJson(view, body);
  else if (trimmed.startsWith("<")) paintMarkup(view, body);
  else view.appendChild(document.createTextNode(body));
}
function highlightSpan(className, text) {
  const node = document.createElement("span");
  node.className = className;
  node.textContent = text;
  return node;
}
function paintJson(parent, text) {
  const re = /("(?:\\.|[^"\\])*")(\s*:)?|\b(true|false|null)\b|-?\d+(?:\.\d+)?(?:[eE][+-]?\d+)?|[{}\[\],]/g;
  let last = 0;
  let match;
  while ((match = re.exec(text))) {
    if (match.index > last) parent.appendChild(document.createTextNode(text.slice(last, match.index)));
    if (match[1]) {
      parent.appendChild(highlightSpan(match[2] ? "hl-key" : "hl-str", match[1]));
      if (match[2]) parent.appendChild(document.createTextNode(match[2]));
    } else if (match[3]) {
      parent.appendChild(highlightSpan("hl-lit", match[3]));
    } else if ("{}[],".includes(match[0])) {
      parent.appendChild(highlightSpan("hl-punct", match[0]));
    } else {
      parent.appendChild(highlightSpan("hl-num", match[0]));
    }
    last = match.index + match[0].length;
  }
  if (last < text.length) parent.appendChild(document.createTextNode(text.slice(last)));
}
function paintMarkup(parent, text) {
  const re = /<!--[\s\S]*?-->|<\/?[A-Za-z][^>\n]*>|&[#A-Za-z0-9]+;/g;
  let last = 0;
  let match;
  while ((match = re.exec(text))) {
    if (match.index > last) parent.appendChild(document.createTextNode(text.slice(last, match.index)));
    const token = match[0];
    const kind = token.startsWith("&") ? "hl-num" : "hl-h";
    parent.appendChild(highlightSpan(kind, token));
    last = match.index + token.length;
  }
  if (last < text.length) parent.appendChild(document.createTextNode(text.slice(last)));
}
function showOutput(raw, req) {
  const box = $("output");
  box.hidden = false;
  box.classList.remove("collapsed");
  $("output-toggle").textContent = "Hide response";
  $("output-meta").textContent = [req.method, req.label].filter(Boolean).join("  ");
  $("output-name").value = req.name;
  paintOutput(raw);
}
async function runRequest() {
  const req = requestForSend();
  if (!req) { toast("Select a row first"); return; }
  if (req.error) { toast(req.error); return; }
  const button = $("run");
  button.disabled = true;
  toast("Running…");
  try {
    const response = await fetch("/api/run", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({
        url: req.url,
        method: req.method,
        headers: req.headers,
        body: req.body
      })
    });
    const data = await response.json();
    if (!data.ok) {
      toast(data.message || "The request failed");
      return;
    }
    showOutput(data.raw || "", req);
    toast(data.truncated ? "Response truncated at 500 KB" : (data.message || "Response received."));
  } catch (err) {
    toast("Could not reach the viewer");
  } finally {
    button.disabled = false;
  }
}
$("run").addEventListener("click", runRequest);
$("output-toggle").addEventListener("click", () => {
  const box = $("output");
  const collapsed = box.classList.toggle("collapsed");
  $("output-toggle").textContent = collapsed ? "Show response" : "Hide response";
});
$("output-save").addEventListener("click", async () => {
  if (!state.outputText) { toast("Run a request first"); return; }
  const button = $("output-save");
  button.disabled = true;
  try {
    const response = await fetch("/api/save", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ name: $("output-name").value, text: state.outputText })
    });
    const data = await response.json();
    toast(data.message || (data.ok ? "Saved" : "Could not save"));
  } catch (err) {
    toast("Could not reach the viewer");
  } finally {
    button.disabled = false;
  }
});
$("reload").addEventListener("click", () => {
  const file = activeFile();
  load(file && (file.source || file.name)).catch(() => toast("Refresh failed"));
});
async function importPath(path) {
  const response = await fetch("/api/import", {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({ path })
  });
  const data = await response.json();
  toast(data.message || (data.ok ? "Imported" : "Could not import"));
  if (!data.ok) return;
  $("import-path").value = "";
  const current = activeFile();
  await load(current && current.source);
  const matches = state.scan.files
    .map((file, index) => ({ file, index }))
    .filter((item) => item.file.source === data.path || item.file.imported === data.path);
  if (!matches.length) return;
  matches.sort((a, b) => b.file.rows.length - a.file.rows.length);
  state.active = matches[0].index;
  state.only = null;
  state.prefix = null;
  state.cursor = 0;
  state.openKey = "";
  render();
}
async function removeImport(path) {
  const current = activeFile();
  const response = await fetch("/api/unimport", {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({ path })
  });
  const data = await response.json();
  toast(data.message || (data.ok ? "Removed" : "Could not remove"));
  if (data.ok) await load(current && current.source);
}
$("import-form").addEventListener("submit", (event) => {
  event.preventDefault();
  const path = $("import-path").value.trim();
  if (!path) { toast("Type a file or folder path"); return; }
  importPath(path).catch(() => toast("Could not reach the viewer"));
});
$("reset").addEventListener("click", () => {
  state.q = "";
  qEl.value = "";
  state.classes = {1: true, 2: true, 3: true, 4: true, 5: true};
  state.hide = true;
  $("hide").checked = true;
  state.threshold = 5;
  $("threshold").value = "5";
  state.only = null;
  state.prefix = null;
  state.sort = "rare";
  state.dir = "asc";
  state.cursor = 0;
  state.openKey = "";
  resetEditor();
  render();
});
document.addEventListener("keydown", (event) => {
  const typing = event.target && (event.target.tagName === "INPUT" || event.target.tagName === "TEXTAREA");
  if (event.key === "/" && !typing) {
    event.preventDefault();
    qEl.focus();
    qEl.select();
    return;
  }
  if (typing) {
    if (event.key === "Escape") qEl.blur();
    return;
  }
  const model = viewModel();
  if (!model || !model.rows.length) {
    if (event.key === "h") { state.hide = !state.hide; $("hide").checked = state.hide; render(); }
    return;
  }
  if (event.key === "j" || event.key === "ArrowDown") {
    state.cursor = Math.min(model.rows.length - 1, state.cursor + 1);
    state.cursorKey = rowKey(model.rows[state.cursor]);
    state.keyboard = true;
    event.preventDefault();
    render();
  } else if (event.key === "k" || event.key === "ArrowUp") {
    state.cursor = Math.max(0, state.cursor - 1);
    state.cursorKey = rowKey(model.rows[state.cursor]);
    state.keyboard = true;
    event.preventDefault();
    render();
  } else if (event.key === "Enter") {
    const row = model.rows[state.cursor];
    if (!row) return;
    state.openKey = state.openKey === rowKey(row) ? "" : rowKey(row);
    render();
  } else if ((event.key === "c" || event.key === "y") && !event.ctrlKey && !event.metaKey && !event.altKey) {
    const selected = window.getSelection();
    if (selected && String(selected).trim()) return;
    const row = model.rows[state.cursor];
    if (!row) return;
    copyText(row.url || row.path, "Copied " + (row.path || row.url));
  } else if (event.key === "x" && !event.ctrlKey && !event.metaKey && !event.altKey) {
    copyCurl();
  } else if (event.key === "b" && !event.ctrlKey && !event.metaKey && !event.altKey) {
    const selected = window.getSelection();
    if (selected && String(selected).trim()) return;
    sendToBurp();
  } else if (event.key === "r" && !event.ctrlKey && !event.metaKey && !event.altKey) {
    const selected = window.getSelection();
    if (selected && String(selected).trim()) return;
    runRequest();
  } else if (event.key === "h") {
    state.hide = !state.hide;
    $("hide").checked = state.hide;
    render();
  } else if (event.key === "Escape") {
    state.only = null;
    state.prefix = null;
    state.openKey = "";
    render();
  }
});

load().catch(() => {
  $("where").textContent = "failed to load /api/scan";
});
</script>
</body>
</html>
"""


class Handler(BaseHTTPRequestHandler):
    directory: Path

    def do_GET(self) -> None:  # noqa: N802
        parsed = urllib.parse.urlparse(self.path)
        if parsed.path == "/":
            body = PAGE.encode("utf-8")
            self._send(200, "text/html; charset=utf-8", body)
            return
        if parsed.path == "/api/scan":
            with self.extra_lock:
                extras = list(self.extra_paths)
            body = json.dumps(scan(self.directory, extras)).encode("utf-8")
            self._send(200, "application/json; charset=utf-8", body)
            return
        self._send(404, "text/plain; charset=utf-8", b"not found\n")

    def do_POST(self) -> None:  # noqa: N802
        parsed = urllib.parse.urlparse(self.path)
        route = parsed.path
        if route not in {"/api/burp", "/api/run", "/api/save", "/api/import", "/api/unimport"}:
            self._send(404, "text/plain; charset=utf-8", b"not found\n")
            return
        limit = 2_200_000 if route == "/api/save" else 262144
        try:
            length = int(self.headers.get("Content-Length") or "0")
        except ValueError:
            length = -1
        if length < 0 or length > limit:
            self._reply({"ok": False, "message": "Request is too large."}, 400)
            return
        try:
            incoming = json.loads(self.rfile.read(length) or b"{}")
        except json.JSONDecodeError:
            self._reply({"ok": False, "message": "Expected JSON."}, 400)
            return
        if not isinstance(incoming, dict):
            self._reply({"ok": False, "message": "Expected a JSON object."}, 400)
            return
        headers = incoming.get("headers") or []
        if not isinstance(headers, list):
            headers = []
        if route == "/api/save":
            result = save_response(self.directory, str(incoming.get("name") or ""), str(incoming.get("text") or ""))
            self._reply(result, 200 if result.get("ok") else 400)
            return
        if route == "/api/import":
            result = add_import(self.directory, self.extra_paths, self.extra_lock, str(incoming.get("path") or ""))
            self._reply(result, 200 if result.get("ok") else 400)
            return
        if route == "/api/unimport":
            result = remove_import(self.extra_paths, self.extra_lock, str(incoming.get("path") or ""))
            self._reply(result, 200 if result.get("ok") else 400)
            return
        method = str(incoming.get("method") or "GET")
        url = str(incoming.get("url") or "")
        body = str(incoming.get("body") or "")
        if route == "/api/run":
            result = run_request(method, url, headers, body)
            client_error = "http(s)" in result.get("message", "") or "not installed" in result.get("message", "")
            self._reply(result, 200 if result.get("ok") else (400 if client_error else 502))
            return
        result = send_through_burp(method, url, headers, body)
        self._reply(result, 200 if result.get("ok") else 502)

    def _reply(self, result: dict, status: int) -> None:
        self._send(status, "application/json; charset=utf-8", json.dumps(result).encode())

    def _send(self, status: int, content_type: str, body: bytes) -> None:
        self.send_response(status)
        self.send_header("Content-Type", content_type)
        self.send_header("Content-Length", str(len(body)))
        self.send_header("Cache-Control", "no-store")
        self.send_header("X-Content-Type-Options", "nosniff")
        self.end_headers()
        self.wfile.write(body)

    def log_message(self, fmt: str, *args) -> None:
        sys.stderr.write("%s  %s\n" % (self.log_date_time_string(), fmt % args))


def serve(directory: Path, host: str, port: int, extras: list[Path] | None = None) -> None:
    handler = type(
        "BoundHandler",
        (Handler,),
        {"directory": directory, "extra_paths": list(extras or []), "extra_lock": threading.Lock()},
    )
    server = ThreadingHTTPServer((host, port), handler)
    url = f"http://{host}:{port}"
    print("logburr")
    print(f"  logs  {directory}")
    for extra in extras or []:
        print(f"  also  {extra}")
    print(f"  open  {url}")
    print(f"  burp  {BURP_PROXY}")
    print("  run   direct curl, proxy skipped")
    print("  stop  Ctrl-C")
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        print("\nstopped")
    finally:
        server.server_close()


def main() -> None:
    parser = argparse.ArgumentParser(description="Browse feroxbuster, ffuf, gobuster, and dirsearch logs in the browser.")
    parser.add_argument("directory", nargs="?", default=str(Path(__file__).resolve().parent), help="Directory of log files. Defaults to this script's folder.")
    parser.add_argument("-p", "--port", type=int, default=8877)
    parser.add_argument("-b", "--bind", default="127.0.0.1", help="Address to bind. Defaults to localhost.")
    parser.add_argument("-i", "--import", dest="imports", action="append", default=[], metavar="PATH", help="Also read this log file or directory. Repeat for more than one.")
    parser.add_argument("--check", action="store_true", help="Parse the logs, print a summary, and exit.")
    args = parser.parse_args()
    directory = Path(args.directory).expanduser().resolve()
    if not directory.is_dir():
        sys.exit(f"not a directory: {directory}")
    extras: list[Path] = []
    for raw in args.imports:
        path, message = check_import(raw, directory)
        if path is None:
            sys.exit(message)
        if path not in extras:
            extras.append(path)
    if args.check:
        report = scan(directory, extras)
        if not report["files"]:
            print(f"no log files in {directory}")
            return
        for item in report["files"]:
            target = item["meta"].get("target") or item["note"]
            where = f"  [{item['imported']}]" if item.get("imported") else ""
            print(f"{item['tool']:<12} {item['label']:<28} {len(item['rows']):4} hits  {target}{where}")
        return
    serve(directory, args.bind, args.port, extras)


if __name__ == "__main__":
    main()
