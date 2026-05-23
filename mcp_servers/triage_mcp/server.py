#!/usr/bin/env python3
"""
Triage Agent MCP Server — built with FastMCP
=============================================
Tools:
  1. identify_evidence_type  — format, OS, filesystem, SHA-256
  2. list_artifacts          — artifact inventory via ewfmount + fls
  3. quick_threat_scan       — YARA + ClamAV + path heuristics + strings/grep

Evidence dir : ~/lab/
Mount base   : /tmp/mcp_mounts/
YARA rules   : ~/mcp_server/yara_rules/*.yar
Logs         : ~/mcp_server/logs/mcp_server.log
"""

import asyncio
import hashlib
import logging
import re
import subprocess
import time
from pathlib import Path
from typing import Any

from fastmcp import FastMCP

# ──────────────────────────────────────────────
# Config
# ──────────────────────────────────────────────

LAB_DIR        = Path.home() / "lab"
MOUNT_BASE     = Path("/tmp/mcp_mounts")
YARA_RULES_DIR = Path.home() / "mcp_server" / "yara_rules"
LOG_DIR        = Path.home() / "mcp_server" / "logs"

for d in (MOUNT_BASE, YARA_RULES_DIR, LOG_DIR):
    d.mkdir(parents=True, exist_ok=True)

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(message)s",
    handlers=[
        logging.FileHandler(LOG_DIR / "mcp_server.log"),
        logging.StreamHandler(),
    ],
)
log = logging.getLogger("triage_mcp")

# ──────────────────────────────────────────────
# FastMCP app
# ──────────────────────────────────────────────

mcp = FastMCP(
    name="triage-mcp-server",
    instructions=(
        "Forensic triage MCP server. Exposes three tools: "
        "identify_evidence_type, list_artifacts, quick_threat_scan. "
        "Evidence files must be placed in ~/lab/. "
        "Pass filenames relative to ~/lab/ or absolute paths."
    ),
)

# ──────────────────────────────────────────────
# Suspicious patterns
# ──────────────────────────────────────────────

SUSPICIOUS_PATHS = [
    r"Windows\\Temp\\.*\.(exe|dll|bat|ps1|vbs|js|hta|scr|com|pif)$",
    r"AppData\\Local\\Temp\\.*\.(exe|dll|bat|ps1|vbs)$",
    r"AppData\\Roaming\\.*\.(exe|dll)$",
    r"ProgramData\\.*\.(exe|dll|bat|ps1)$",
    r"Users\\Public\\.*\.(exe|dll|bat|ps1)$",
    r"Recycle\.Bin\\.*\.(exe|dll)$",
    r"\\Windows\\System32\\.*\.(tmp|dat)$",
    r"/tmp/.*\.(sh|elf|py|pl)$",
    r"/dev/shm/.*",
    r"/var/tmp/.*\.(sh|elf)$",
    r"\.ssh/authorized_keys",
    r"/etc/cron\.(d|daily|hourly)/[^/]+$",
]

SUSPICIOUS_EXTENSIONS = {".exe", ".dll", ".bat", ".ps1", ".vbs", ".hta", ".scr", ".pif", ".com"}

NETWORK_IOC_PATTERNS = [
    r"\b185\.220\.\d+\.\d+\b",
    r"\b194\.165\.\d+\.\d+\b",
    r"(?:cmd\.exe|powershell\.exe|wscript\.exe|cscript\.exe)\s+.*(?:/c|/e|EncodedCommand|-enc)\b",
    r"(?:mimikatz|sekurlsa|lsadump|hashdump)",
    r"(?:cobalt.?strike|cobaltstrike|beacon\.dll)",
    r"(?:metasploit|meterpreter)",
    r"(?:net\s+user\s+.*\s+/add|net\s+localgroup\s+administrators)",
    r"(?:reg\s+add.*Run|CurrentVersion\\Run)",
    r"[A-Za-z0-9+/]{60,}={0,2}",  # long base64 blobs
]

# ──────────────────────────────────────────────
# Default YARA rules
# ──────────────────────────────────────────────

DEFAULT_YARA_RULES = """\
rule SuspiciousTempExecutable {
    meta:
        description = "Executable in Temp / suspicious location"
        severity    = "HIGH"
    strings:
        $path1 = "\\\\Temp\\\\" nocase
        $path2 = "\\\\AppData\\\\Local\\\\Temp\\\\" nocase
        $path3 = "/tmp/" nocase
        $mz    = { 4D 5A }
    condition:
        $mz at 0 and any of ($path1, $path2, $path3)
}

rule MimikatzStrings {
    meta:
        description = "Mimikatz credential dumper strings"
        severity    = "CRITICAL"
    strings:
        $a = "sekurlsa" nocase
        $b = "lsadump" nocase
        $c = "mimikatz" nocase
        $d = "wdigest" nocase
    condition:
        2 of them
}

rule CobaltStrikeBeacon {
    meta:
        description = "Cobalt Strike beacon indicators"
        severity    = "CRITICAL"
    strings:
        $a = "cobaltstrike" nocase
        $b = "beacon.dll" nocase
        $c = "ReflectiveLoader" nocase
    condition:
        any of them
}

rule PowerShellEncodedCommand {
    meta:
        description = "PowerShell encoded command execution"
        severity    = "HIGH"
    strings:
        $a = "-EncodedCommand" nocase
        $b = "-enc " nocase
        $c = "FromBase64String" nocase
        $d = "powershell" nocase
    condition:
        $d and any of ($a, $b, $c)
}

rule NetUserAddCommand {
    meta:
        description = "Unauthorized user account creation"
        severity    = "HIGH"
    strings:
        $a = "net user" nocase
        $b = "/add" nocase
        $c = "net localgroup administrators" nocase
    condition:
        ($a and $b) or $c
}

rule SuspiciousRegistryRun {
    meta:
        description = "Registry Run key persistence"
        severity    = "HIGH"
    strings:
        $a = "CurrentVersion\\\\Run" nocase
        $b = "CurrentVersion\\\\RunOnce" nocase
    condition:
        any of them
}
"""


def _ensure_default_yara_rules():
    rule_file = YARA_RULES_DIR / "default_rules.yar"
    if not rule_file.exists():
        rule_file.write_text(DEFAULT_YARA_RULES)
        log.info(f"Wrote default YARA rules → {rule_file}")


# ──────────────────────────────────────────────
# Shared helpers
# ──────────────────────────────────────────────

def _run(cmd: list[str], timeout: int = 60) -> tuple[int, str, str]:
    try:
        r = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout)
        return r.returncode, r.stdout, r.stderr
    except subprocess.TimeoutExpired:
        return -1, "", f"Timed out after {timeout}s: {' '.join(cmd)}"
    except FileNotFoundError:
        return -1, "", f"Tool not found: {cmd[0]}"


def _sha256(path: Path) -> str:
    h = hashlib.sha256()
    with open(path, "rb") as f:
        for chunk in iter(lambda: f.read(1024 * 1024), b""):
            h.update(chunk)
    return h.hexdigest()


def _resolve(file_path: str) -> Path:
    p = Path(file_path)
    if p.is_absolute():
        if p.exists():
            return p
        raise FileNotFoundError(f"Not found: {p}")
    candidate = LAB_DIR / p
    if candidate.exists():
        return candidate
    raise FileNotFoundError(f"Not found: {file_path} (checked {LAB_DIR})")


def _get_partition_offset(image: Path) -> int | None:
    rc, out, _ = _run(["mmls", str(image)], timeout=30)
    if rc != 0:
        return None
    for line in out.splitlines():
        parts = line.split()
        if len(parts) >= 5 and re.match(r"^\d+:", parts[0]):
            if parts[1] not in ("Meta", "-----"):
                try:
                    return int(parts[2])
                except ValueError:
                    continue
    return None


def _mount_ewf(image: Path) -> tuple[Path, str | None]:
    mount_point = MOUNT_BASE / image.stem.replace(" ", "_")
    mount_point.mkdir(parents=True, exist_ok=True)

    rc, _, _ = _run(["mountpoint", "-q", str(mount_point)])
    if rc == 0:
        return mount_point, None  # already mounted

    rc, _, err = _run(["ewfmount", str(image), str(mount_point)], timeout=30)
    if rc != 0:
        return mount_point, f"ewfmount failed: {err.strip()}"

    log.info(f"Mounted {image.name} → {mount_point}")
    return mount_point, None


def _fls_lines(image: Path, is_ewf: bool) -> list[str]:
    if is_ewf:
        mount_point, err = _mount_ewf(image)
        if err:
            log.warning(err)
            return []
        ewf1   = mount_point / "ewf1"
        target = ewf1 if ewf1.exists() else mount_point
        rc, out, _ = _run(["fls", "-r", "-p", str(target)], timeout=60)
    else:
        offset = _get_partition_offset(image)
        cmd    = ["fls", "-r", "-p", str(image)]
        if offset:
            cmd = ["fls", "-r", "-p", "-o", str(offset), str(image)]
        rc, out, _ = _run(cmd, timeout=60)

    return out.splitlines() if rc == 0 else []


def _path_in(lines: list[str], fragment: str) -> bool:
    f = fragment.lower()
    return any(f in l.lower() for l in lines)


def _count_ext(lines: list[str], directory: str, ext: str) -> int:
    d, e = directory.lower(), ext.lower()
    return sum(1 for l in lines if d in l.lower() and l.lower().endswith(e))


# ──────────────────────────────────────────────
# Tool 1 — identify_evidence_type
# ──────────────────────────────────────────────

@mcp.tool()
async def identify_evidence_type(file_path: str) -> dict[str, Any]:
    """
    Identify a forensic evidence file: format, OS, filesystem, and SHA-256 hash.

    Supports E01/EWF disk images, raw DD images, and memory dumps.
    Pass a filename relative to ~/lab/ or an absolute path.
    """
    t0 = time.time()
    log.info(f"[identify_evidence_type] {file_path}")

    try:
        fp = _resolve(file_path)
    except FileNotFoundError as e:
        return {"status": "ERROR", "message": str(e)}

    suffix = fp.suffix.lower()
    stat   = fp.stat()

    result: dict[str, Any] = {
        "file_name": fp.name,
        "file_path": str(fp),
        "size_bytes": stat.st_size,
        "size_gb":    round(stat.st_size / (1024 ** 3), 2),
        "sha256":     _sha256(fp),
    }

    _, file_out, _ = _run(["file", str(fp)])
    result["file_command_output"] = file_out.strip()

    ewf_exts = {".e01", ".e02", ".ex01", ".ewf"}
    is_ewf   = suffix in ewf_exts or "EWF" in file_out or "Expert Witness" in file_out
    is_mem   = any(k in fp.name.lower() for k in ("memory", "mem", "ram", "dump")) \
               and suffix in {".raw", ".dmp", ".mem", ".vmem", ".lime"}
    is_arch  = suffix in {".7z", ".zip", ".gz", ".tar", ".bz2"}

    if is_ewf:
        result["evidence_type"] = "disk_image"
        result["format"]        = "E01/EWF"

        _, ewf_out, _ = _run(["ewfinfo", str(fp)], timeout=20)
        for line in ewf_out.splitlines():
            if "Media size"       in line: result["ewf_media_size"]   = line.split(":")[-1].strip()
            if "Bytes per sector" in line: result["bytes_per_sector"] = line.split(":")[-1].strip()

        _, mmls_out, _ = _run(["mmls", str(fp)], timeout=30)
        if mmls_out:
            result["partition_table"] = mmls_out.strip()

    elif is_mem:
        result["evidence_type"] = "memory_dump"
        result["format"]        = suffix.upper().lstrip(".")
        result["compressed"]    = is_arch

        rc, vol_out, _ = _run(["vol", "-f", str(fp), "windows.info"], timeout=60)
        if rc == 0 and "Kernel Base" in vol_out:
            result["os_detected"]     = "Windows"
            result["volatility_info"] = vol_out[:500]
        else:
            rc2, vol2, _ = _run(["vol", "-f", str(fp), "linux.info"], timeout=60)
            if rc2 == 0:
                result["os_detected"]     = "Linux"
                result["volatility_info"] = vol2[:500]
            else:
                result["os_detected"]     = "Unknown"
                result["volatility_note"] = (
                    "Volatility3 not available or unsupported format. "
                    "Install: pip install volatility3 --break-system-packages"
                )

    elif is_arch:
        result["evidence_type"] = "archive"
        result["format"]        = suffix.upper().lstrip(".")
        result["note"]          = "Extract to determine contents"

    else:
        result["evidence_type"] = "disk_image"
        result["format"]        = "RAW/DD"
        _, mmls_out, _ = _run(["mmls", str(fp)], timeout=30)
        if mmls_out:
            result["partition_table"] = mmls_out.strip()

    # OS + filesystem for disk images
    if result["evidence_type"] == "disk_image":
        offset     = _get_partition_offset(fp)
        fsstat_cmd = ["fsstat", str(fp)] if not offset else ["fsstat", "-o", str(offset), str(fp)]
        _, fsstat_out, _ = _run(fsstat_cmd, timeout=30)

        fsl = fsstat_out.lower()
        if   "ntfs" in fsl: fs = "NTFS"
        elif "fat"  in fsl: fs = "FAT32"
        elif "ext"  in fsl: fs = "EXT4/3/2"
        elif "hfs"  in fsl: fs = "HFS+/APFS"
        else:               fs = "Unknown"
        result["filesystem"] = fs

        _, str_out, _ = _run(["strings", "-n", "8", str(fp)], timeout=20)
        s = str_out.lower()
        if   "windows 10"          in s: os_d = "Windows 10"
        elif "windows 11"          in s: os_d = "Windows 11"
        elif "windows 7"           in s: os_d = "Windows 7"
        elif "windows server 2019" in s: os_d = "Windows Server 2019"
        elif "windows server 2016" in s: os_d = "Windows Server 2016"
        elif "windows server"      in s: os_d = "Windows Server"
        elif "ubuntu"              in s: os_d = "Ubuntu Linux"
        elif "debian"              in s: os_d = "Debian Linux"
        elif "centos" in s or "rhel" in s: os_d = "CentOS/RHEL Linux"
        elif fs == "NTFS":               os_d = "Windows (version unknown)"
        elif fs == "EXT4/3/2":           os_d = "Linux (distro unknown)"
        elif fs == "HFS+/APFS":          os_d = "macOS"
        else:                            os_d = "Unknown"
        result["os_detected"] = os_d

    result["duration_ms"] = round((time.time() - t0) * 1000)
    return result


# ──────────────────────────────────────────────
# Tool 2 — list_artifacts
# ──────────────────────────────────────────────

@mcp.tool()
async def list_artifacts(image_path: str) -> dict[str, Any]:
    """
    Inventory forensic artifacts on a disk image.

    Mounts E01 images with ewfmount, then runs fls recursively to
    detect Registry hives, Prefetch, Event Logs, MFT, Browser history,
    Jump Lists, Scheduled Tasks, SRUM, AmCache, and more.

    Returns dispatch flags (has_registry, has_event_logs, has_memory,
    has_sam_database, has_network_artifacts) used by the Triage Agent
    to decide which specialist agents to call.
    """
    t0 = time.time()
    log.info(f"[list_artifacts] {image_path}")

    try:
        fp = _resolve(image_path)
    except FileNotFoundError as e:
        return {"status": "ERROR", "message": str(e)}

    is_ewf = fp.suffix.lower() in {".e01", ".e02", ".ex01", ".ewf"}
    lines  = _fls_lines(fp, is_ewf)

    if not lines:
        return {
            "status":     "WARNING",
            "message":    "fls returned no output — image may be unreadable or unsupported format",
            "image_path": str(fp),
        }

    is_windows = any("windows" in l.lower() for l in lines[:300])
    is_linux   = any("/etc/passwd" in l.lower() or "var/log" in l.lower() for l in lines)

    arts: dict[str, Any] = {
        "image_path":          str(fp),
        "total_files_indexed": len(lines),
        "scan_method":         "fls_recursive",
    }

    if is_windows or not is_linux:
        arts["os_family"] = "Windows"

        hives = [h for h in ("SOFTWARE", "SYSTEM", "SAM", "SECURITY", "DEFAULT")
                 if _path_in(lines, f"config/{h}")]
        arts["has_registry"]   = bool(hives)
        arts["registry_hives"] = hives

        pf = _count_ext(lines, "Prefetch", ".pf")
        arts["has_prefetch"]   = pf > 0
        arts["prefetch_count"] = pf

        evtx = [
            Path(re.search(r":\s+(.+)$", l).group(1)).name
            for l in lines
            if ".evtx" in l.lower() and re.search(r":\s+(.+)$", l)
        ]
        arts["has_event_logs"]  = bool(evtx)
        arts["event_log_files"] = evtx[:20]
        arts["event_log_count"] = len(evtx)

        arts["has_mft"]             = _path_in(lines, "$MFT")
        arts["has_usnjrnl"]         = _path_in(lines, "$UsnJrnl")
        arts["has_pagefile"]        = _path_in(lines, "pagefile.sys")
        arts["has_hiberfil"]        = _path_in(lines, "hiberfil.sys")
        arts["has_jump_lists"]      = _path_in(lines, "AutomaticDestinations") or _path_in(lines, "CustomDestinations")
        arts["has_lnk_files"]       = _count_ext(lines, "Recent", ".lnk") > 0
        arts["has_scheduled_tasks"] = _path_in(lines, "System32/Tasks") or _path_in(lines, "SysWOW64/Tasks")
        arts["has_startup_items"]   = _path_in(lines, "Startup")
        arts["has_recycle_bin"]     = _path_in(lines, "$Recycle.Bin")
        arts["has_amcache"]         = _path_in(lines, "Amcache.hve")
        arts["has_srum"]            = _path_in(lines, "SRUDB.dat")
        arts["has_sam_database"]    = _path_in(lines, "config/SAM")

        chrome  = _path_in(lines, "Chrome")
        firefox = _path_in(lines, "Firefox")
        edge    = _path_in(lines, "Edge")
        arts["has_browser_artifacts"] = chrome or firefox or edge
        arts["browsers_found"]        = [b for b, f in [("Chrome", chrome), ("Firefox", firefox), ("Edge", edge)] if f]

        # Dispatch flags
        arts["has_memory"]            = False  # disk only; set True when memory dump also provided
        arts["has_network_artifacts"] = arts["has_srum"] or arts["has_event_logs"]

    elif is_linux:
        arts["os_family"]        = "Linux"
        arts["has_syslog"]       = _path_in(lines, "var/log/syslog") or _path_in(lines, "var/log/messages")
        arts["has_auth_log"]     = _path_in(lines, "auth.log") or _path_in(lines, "secure")
        arts["has_bash_history"] = _path_in(lines, ".bash_history")
        arts["has_crontabs"]     = _path_in(lines, "cron")
        arts["has_passwd"]       = _path_in(lines, "etc/passwd")
        arts["has_shadow"]       = _path_in(lines, "etc/shadow")
        arts["has_ssh_keys"]     = _path_in(lines, "authorized_keys")
        arts["has_journal"]      = _path_in(lines, "var/log/journal")

        arts["has_registry"]          = False
        arts["has_prefetch"]          = False
        arts["has_sam_database"]      = False
        arts["has_memory"]            = False
        arts["has_event_logs"]        = arts.get("has_syslog") or arts.get("has_auth_log")
        arts["has_network_artifacts"] = arts.get("has_journal") or arts.get("has_auth_log")

    else:
        arts["os_family"] = "Unknown"

    arts["duration_ms"] = round((time.time() - t0) * 1000)
    return arts


# ──────────────────────────────────────────────
# Tool 3 — quick_threat_scan
# ──────────────────────────────────────────────

@mcp.tool()
async def quick_threat_scan(image_path: str) -> dict[str, Any]:
    """
    Fast IOC scan on a forensic evidence file.

    Runs four checks:
      1. Path heuristics  — executables in suspicious locations
      2. YARA             — signature matching from ~/mcp_server/yara_rules/
      3. ClamAV           — malware scan via clamdscan (daemon must be running)
      4. strings + regex  — network IOCs, encoded commands, known tool signatures

    Returns overall_risk (LOW / MEDIUM / HIGH / CRITICAL) and
    detailed hit lists per check.
    """
    t0 = time.time()
    log.info(f"[quick_threat_scan] {image_path}")
    _ensure_default_yara_rules()

    try:
        fp = _resolve(image_path)
    except FileNotFoundError as e:
        return {"status": "ERROR", "message": str(e)}

    is_ewf = fp.suffix.lower() in {".e01", ".e02", ".ex01", ".ewf"}

    result: dict[str, Any] = {
        "image_path":       str(fp),
        "suspicious_files": [],
        "yara_hits":        [],
        "clamav_hits":      [],
        "network_ioc_hits": [],
        "command_ioc_hits": [],
    }

    # ── 1. Path heuristics via fls ──
    lines = _fls_lines(fp, is_ewf)
    suspicious_files = []
    for line in lines:
        m = re.search(r":\s+(.+)$", line)
        if not m:
            continue
        fpath = m.group(1).strip()
        for pat in SUSPICIOUS_PATHS:
            if re.search(pat, fpath, re.IGNORECASE):
                ext  = Path(fpath).suffix.lower()
                risk = "HIGH" if ext in SUSPICIOUS_EXTENSIONS else "MEDIUM"
                suspicious_files.append({
                    "path":   fpath,
                    "reason": f"Suspicious location: {pat}",
                    "risk":   risk,
                })
                break

    result["suspicious_files"] = suspicious_files[:50]

    # ── 2. YARA ──
    yara_hits = []
    yar_files = list(YARA_RULES_DIR.glob("*.yar")) + list(YARA_RULES_DIR.glob("*.yara"))

    if yar_files:
        for yar in yar_files:
            rc, out, _ = _run(["yara", "-r", str(yar), str(fp)], timeout=120)
            if rc == 0 and out.strip():
                for line in out.strip().splitlines():
                    parts    = line.strip().split(" ", 1)
                    rule     = parts[0] if parts else "Unknown"
                    severity = "CRITICAL" if rule in ("MimikatzStrings", "CobaltStrikeBeacon") else "HIGH"
                    yara_hits.append({
                        "rule":        rule,
                        "file":        parts[1] if len(parts) > 1 else str(fp),
                        "rule_source": yar.name,
                        "severity":    severity,
                    })
    else:
        result["yara_note"] = f"No .yar files found in {YARA_RULES_DIR}"

    result["yara_hits"] = yara_hits

    # ── 3. ClamAV ──
    clamav_hits = []
    rc, clam_out, _ = _run(["clamdscan", "--no-summary", str(fp)], timeout=300)

    for line in clam_out.splitlines():
        if "FOUND" in line:
            parts = line.rsplit(":", 1)
            if len(parts) == 2:
                clamav_hits.append({
                    "file":      parts[0].strip(),
                    "signature": parts[1].replace("FOUND", "").strip(),
                    "risk":      "CRITICAL",
                })

    if rc == 2:
        result["clamav_note"] = (
            "clamdscan error — daemon may not be running. "
            "Fix: sudo service clamav-daemon start"
        )

    result["clamav_hits"] = clamav_hits

    # ── 4. strings + regex IOC grep ──
    network_hits = []
    command_hits = []

    _, strings_out, _ = _run(["strings", "-n", "8", str(fp)], timeout=60)

    if strings_out:
        for pat in NETWORK_IOC_PATTERNS:
            matches = re.findall(pat, strings_out, re.IGNORECASE | re.MULTILINE)
            for match in matches[:5]:
                is_cmd = any(k in pat for k in ["cmd", "powershell", "net user", "reg add"])
                entry  = {"matched_string": match[:200], "pattern": pat, "risk": "HIGH"}
                (command_hits if is_cmd else network_hits).append(entry)

    result["network_ioc_hits"] = network_hits[:20]
    result["command_ioc_hits"] = command_hits[:20]

    # ── Overall risk ──
    critical = (
        sum(1 for h in yara_hits   if h["severity"] == "CRITICAL") +
        sum(1 for h in clamav_hits if h["risk"]     == "CRITICAL")
    )
    high = (
        sum(1 for f in suspicious_files if f["risk"] == "HIGH") +
        sum(1 for h in yara_hits        if h["severity"] == "HIGH") +
        len(network_hits) + len(command_hits)
    )

    if   critical > 0: overall = "CRITICAL"
    elif high >= 3:    overall = "HIGH"
    elif high > 0:     overall = "MEDIUM"
    else:              overall = "LOW"

    result["overall_risk"] = overall
    result["summary"] = {
        "suspicious_file_count": len(suspicious_files),
        "yara_hit_count":        len(yara_hits),
        "clamav_hit_count":      len(clamav_hits),
        "network_ioc_count":     len(network_hits),
        "command_ioc_count":     len(command_hits),
        "overall_risk":          overall,
    }

    result["duration_ms"] = round((time.time() - t0) * 1000)
    return result


# ──────────────────────────────────────────────
# Entry point
# ──────────────────────────────────────────────

if __name__ == "__main__":
    log.info("-" * 60)
    log.info("Triage MCP Server (FastMCP) starting")
    log.info(f"  Lab dir    : {LAB_DIR}")
    log.info(f"  Mount base : {MOUNT_BASE}")
    log.info(f"  YARA rules : {YARA_RULES_DIR}")
    log.info(f"  Logs       : {LOG_DIR}")
    log.info("-" * 60)

    _ensure_default_yara_rules()
    mcp.run()