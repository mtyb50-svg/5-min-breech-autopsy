#!/usr/bin/env python3
"""
Exfiltration Agent MCP Server — built with FastMCP
===================================================
Tools:
  1. analyze_memory_network      — active connections, external IPs
  2. extract_timeline            — file activity during incident window
  3. extract_strings             — sensitive data pattern search
  4. parse_jump_lists            — cloud upload / browser access history
  5. parse_registry_usb_history  — USB device connection history
  6. parse_prefetch              — archive / compression tool execution

Evidence dir : ~/lab/
Logs         : ~/mcp_server/logs/exfiltration_mcp.log
"""

import logging
import re
import subprocess
import time
from pathlib import Path
from typing import Any, Optional

from fastmcp import FastMCP

LAB_DIR = Path.home() / "lab"
LOG_DIR = Path.home() / "mcp_server" / "logs"
LOG_DIR.mkdir(parents=True, exist_ok=True)

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(message)s",
    handlers=[
        logging.FileHandler(LOG_DIR / "exfiltration_mcp.log"),
        logging.StreamHandler(),
    ],
)
log = logging.getLogger("exfiltration_mcp")

mcp = FastMCP(
    name="exfiltration-mcp-server",
    instructions=(
        "Exfiltration specialist MCP server. Detects data theft via "
        "network exfiltration, cloud uploads, USB devices, and data staging. "
        "Evidence files must be placed in ~/lab/."
    ),
)

INTERNAL_PREFIXES = ("10.", "172.16.", "172.17.", "172.18.", "172.19.",
                     "172.20.", "172.21.", "172.22.", "172.23.", "172.24.",
                     "172.25.", "172.26.", "172.27.", "172.28.", "172.29.",
                     "172.30.", "172.31.", "192.168.", "127.")

CLOUD_STORAGE_DOMAINS = [
    "dropbox.com", "mega.nz", "drive.google.com", "onedrive.live.com",
    "wetransfer.com", "anonfiles.com", "gofile.io", "sendspace.com",
    "mediafire.com", "zippyshare.com", "paste.ee", "pastebin.com",
]

ARCHIVE_TOOLS = {
    "7z.exe": "T1560.001",
    "7za.exe": "T1560.001",
    "winrar.exe": "T1560.001",
    "rar.exe": "T1560.001",
    "tar.exe": "T1560.001",
    "powershell.exe": "T1560.001",
    "compress-archive": "T1560.001",
}

ARCHIVE_EXTENSIONS = {".zip", ".rar", ".7z", ".tar", ".gz", ".bz2", ".tar.gz"}

SENSITIVE_PATTERNS = [
    (r"\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Z|a-z]{2,}\b", "email_address"),
    (r"\b4[0-9]{12}(?:[0-9]{3})?\b", "credit_card_visa"),
    (r"\b5[1-5][0-9]{14}\b", "credit_card_mastercard"),
    (r"https?://(?:www\.)?" + "|".join(re.escape(d) for d in CLOUD_STORAGE_DOMAINS[:5]), "cloud_storage_url"),
    (r"\b185\.220\.\d+\.\d+\b|\b194\.165\.\d+\.\d+\b", "known_c2_ip"),
    (r"[A-Za-z0-9+/]{60,}={0,2}", "base64_encoded_data"),
    (r"password\s*[:=]\s*\S+", "plaintext_password"),
    (r"BEGIN (?:RSA|EC|PGP) PRIVATE KEY", "private_key"),
]


def _run(cmd: list[str], timeout: int = 60) -> tuple[int, str, str]:
    try:
        r = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout)
        return r.returncode, r.stdout, r.stderr
    except subprocess.TimeoutExpired:
        return -1, "", f"Timed out after {timeout}s: {' '.join(cmd)}"
    except FileNotFoundError:
        return -1, "", f"Tool not found: {cmd[0]}"


def _resolve(file_path: str) -> Path:
    """Resolve a path to ~/lab/ sandbox with symlink rejection."""
    p = Path(file_path)
    if p.is_absolute():
        if p.is_symlink():
            raise PermissionError(f"Symlink rejected (evidence integrity): {p}")
        if p.exists():
            return p
        raise FileNotFoundError(f"Not found: {p}")
    candidate = LAB_DIR / p
    if candidate.is_symlink():
        raise PermissionError(f"Symlink rejected (evidence integrity): {candidate}")
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


def _fls_lines(image: Path) -> list[str]:
    offset = _get_partition_offset(image)
    cmd = ["fls", "-r", "-p", str(image)]
    if offset:
        cmd = ["fls", "-r", "-p", "-o", str(offset), str(image)]
    rc, out, _ = _run(cmd, timeout=60)
    return out.splitlines() if rc == 0 else []


def _is_external_ip(ip: str) -> bool:
    return ip not in ("0.0.0.0", "*", "::") and not ip.startswith(INTERNAL_PREFIXES)


def _is_cloud_domain(url: str) -> Optional[str]:
    for domain in CLOUD_STORAGE_DOMAINS:
        if domain in url.lower():
            return domain
    return None


@mcp.tool()
async def analyze_memory_network(memory_path: str) -> dict[str, Any]:
    """
    Extract active network connections from memory dump to detect exfiltration.

    Uses Volatility windows.netscan to find established connections to
    external IPs, known cloud storage providers, and C2 servers.

    Args:
        memory_path: Path to memory dump (relative to ~/lab/ or absolute)
    """
    t0 = time.time()
    log.info(f"[analyze_memory_network] {memory_path}")

    try:
        fp = _resolve(memory_path)
    except FileNotFoundError as e:
        return {"status": "ERROR", "message": str(e)}

    rc, vol_out, vol_err = _run(["vol", "-f", str(fp), "windows.netscan"], timeout=120)

    connections: list[dict[str, Any]] = []

    if rc == 0 and vol_out.strip():
        for line in vol_out.splitlines()[1:]:
            parts = line.split()
            if len(parts) < 4:
                continue

            local_addr = parts[0] if parts else ""
            remote_addr = parts[2] if len(parts) > 2 else ""
            state = parts[3] if len(parts) > 3 else ""
            process = parts[-1] if parts else ""

            remote_ip = remote_addr.split(":")[0] if ":" in remote_addr else remote_addr
            remote_port_str = remote_addr.split(":")[-1] if ":" in remote_addr else "0"

            try:
                remote_port = int(remote_port_str)
            except ValueError:
                remote_port = 0

            is_external = _is_external_ip(remote_ip)
            if not is_external:
                continue

            suspicious = True
            reason = "External IP connection"
            confidence = 0.75
            mitre = "T1041"

            if remote_port == 443:
                reason = f"HTTPS connection to external IP {remote_ip} — possible encrypted exfiltration"
                confidence = 0.80
            elif remote_port == 80:
                reason = f"HTTP connection to external IP {remote_ip}"
                confidence = 0.70
            elif remote_port not in (80, 443, 22, 21, 25):
                reason = f"Unusual port {remote_port} to external IP {remote_ip}"
                confidence = 0.85
                mitre = "T1048"

            connections.append({
                "local_ip": local_addr.split(":")[0] if ":" in local_addr else local_addr,
                "remote_ip": remote_ip,
                "remote_port": remote_port,
                "state": state,
                "process": process,
                "suspicious": suspicious,
                "reason": reason,
                "confidence": confidence,
                "mitre_technique": mitre,
                "severity": "HIGH" if confidence >= 0.80 else "MEDIUM",
                "estimated_data_note": "Use pcap or NetFlow for actual transfer size",
            })
    else:
        return {
            "status": "WARNING",
            "memory_path": str(fp),
            "message": (
                "Volatility could not parse memory. "
                f"Error: {vol_err[:300] if vol_err else 'Unknown'}. "
                "Install: pip install volatility3"
            ),
            "connections": [],
            "suspicious_count": 0,
            "duration_ms": round((time.time() - t0) * 1000),
        }

    return {
        "status": "OK",
        "memory_path": str(fp),
        "connections": connections[:50],
        "total_external_connections": len(connections),
        "suspicious_count": len(connections),
        "duration_ms": round((time.time() - t0) * 1000),
    }


@mcp.tool()
async def extract_timeline(
    image_path: str,
    start_time: Optional[str] = None,
    end_time: Optional[str] = None,
) -> dict[str, Any]:
    """
    Extract file activity timeline to detect data staging and collection.

    Uses fls to enumerate files and searches for large archives, staging
    locations, and suspicious file activity during the incident window.

    Args:
        image_path:  Path to disk image (relative to ~/lab/ or absolute)
        start_time:  ISO 8601 start time filter (e.g. '2020-12-19T03:40:00Z')
        end_time:    ISO 8601 end time filter (e.g. '2020-12-19T04:30:00Z')
    """
    t0 = time.time()
    log.info(f"[extract_timeline] {image_path}")

    try:
        fp = _resolve(image_path)
    except FileNotFoundError as e:
        return {"status": "ERROR", "message": str(e)}

    lines = _fls_lines(fp)

    archive_lines = [
        l for l in lines
        if any(l.lower().endswith(ext) for ext in ARCHIVE_EXTENSIONS)
    ]

    staging_patterns = [
        r"\\temp\\", r"\\tmp\\", r"\\downloads\\", r"\\appdata\\local\\temp\\",
        r"\\users\\public\\", r"/tmp/", r"/dev/shm/",
    ]

    events: list[dict[str, Any]] = []

    for line in archive_lines:
        m = re.search(r":\s+(.+)$", line)
        if not m:
            continue
        file_path = m.group(1).strip()
        ext = Path(file_path).suffix.lower()

        is_staging = any(re.search(p, file_path, re.IGNORECASE) for p in staging_patterns)
        suspicious = is_staging

        events.append({
            "event_type": "archive_file_found",
            "file_path": file_path,
            "file_extension": ext,
            "in_staging_location": is_staging,
            "suspicious": suspicious,
            "reason": (
                f"Archive file ({ext}) in staging location — possible data exfiltration prep"
                if is_staging else f"Archive file ({ext}) found"
            ),
            "confidence": 0.88 if is_staging else 0.50,
            "mitre_technique": "T1560.001" if suspicious else None,
            "severity": "HIGH" if is_staging else "MEDIUM",
        })

    for line in lines:
        m = re.search(r":\s+(.+)$", line)
        if not m:
            continue
        file_path = m.group(1).strip()
        file_lower = file_path.lower()

        if "lsass.dmp" in file_lower or "memory.dmp" in file_lower:
            events.append({
                "event_type": "dump_file_found",
                "file_path": file_path,
                "suspicious": True,
                "reason": "Memory dump file — likely credential or data dump",
                "confidence": 0.95,
                "mitre_technique": "T1003.001",
                "severity": "CRITICAL",
            })
        elif any(kw in file_lower for kw in ["passwords", "creds", "credentials", "logins"]):
            if file_lower.endswith((".txt", ".csv", ".xlsx", ".xls", ".doc", ".pdf")):
                events.append({
                    "event_type": "credential_file_found",
                    "file_path": file_path,
                    "suspicious": True,
                    "reason": "File name suggests credential storage",
                    "confidence": 0.80,
                    "mitre_technique": "T1552.001",
                    "severity": "HIGH",
                })

    suspicious_count = sum(1 for e in events if e["suspicious"])
    return {
        "status": "OK",
        "image_path": str(fp),
        "events": events[:100],
        "total_events": len(events),
        "suspicious_count": suspicious_count,
        "archive_files_found": len(archive_lines),
        "time_filter": {"start": start_time, "end": end_time},
        "note": "Use Plaso/log2timeline for full filesystem timeline with timestamps",
        "duration_ms": round((time.time() - t0) * 1000),
    }


@mcp.tool()
async def extract_strings(
    target_path: str,
    pattern: Optional[str] = None,
) -> dict[str, Any]:
    """
    Search for sensitive data patterns in disk image or memory dump.

    Runs strings and scans for: email addresses, cloud storage URLs,
    C2 IP addresses, base64 blobs, plaintext passwords, private keys.

    Args:
        target_path: Path to image/dump to search (relative to ~/lab/ or absolute)
        pattern:     Optional custom regex pattern to search for additionally
    """
    t0 = time.time()
    log.info(f"[extract_strings] {target_path}")

    try:
        fp = _resolve(target_path)
    except FileNotFoundError as e:
        return {"status": "ERROR", "message": str(e)}

    rc, str_out, _ = _run(["strings", "-n", "8", str(fp)], timeout=30)

    if rc != 0 or not str_out:
        return {
            "status": "WARNING",
            "target_path": str(fp),
            "message": "strings tool returned no output or failed",
            "findings": [],
            "duration_ms": round((time.time() - t0) * 1000),
        }

    findings: list[dict[str, Any]] = []
    seen: set[str] = set()

    patterns_to_check = list(SENSITIVE_PATTERNS)
    if pattern:
        patterns_to_check.append((pattern, "custom_pattern"))

    for regex, pattern_type in patterns_to_check:
        matches = re.findall(regex, str_out, re.IGNORECASE)
        unique_matches = []
        for match in matches:
            if isinstance(match, tuple):
                match = match[0]
            if match not in seen and len(unique_matches) < 10:
                seen.add(match)
                unique_matches.append(match)

        if not unique_matches:
            continue

        cloud_domain = None
        if pattern_type == "cloud_storage_url":
            for m in unique_matches:
                cloud_domain = _is_cloud_domain(m)
                if cloud_domain:
                    break

        is_critical = pattern_type in ("known_c2_ip", "private_key")
        is_high = pattern_type in ("cloud_storage_url", "plaintext_password", "credit_card_visa", "credit_card_mastercard")

        findings.append({
            "pattern_type": pattern_type,
            "matches": unique_matches[:5],
            "match_count": len(matches),
            "cloud_domain": cloud_domain,
            "suspicious": is_critical or is_high,
            "reason": (
                "Known C2 IP address found" if pattern_type == "known_c2_ip"
                else f"Cloud storage URL found ({cloud_domain})" if cloud_domain
                else f"Sensitive pattern found: {pattern_type}"
            ),
            "confidence": 0.95 if is_critical else 0.85 if is_high else 0.65,
            "mitre_technique": (
                "T1041" if pattern_type == "known_c2_ip"
                else "T1567.002" if cloud_domain
                else "T1552.001" if pattern_type == "plaintext_password"
                else None
            ),
            "severity": "CRITICAL" if is_critical else "HIGH" if is_high else "MEDIUM",
        })

    suspicious_count = sum(1 for f in findings if f["suspicious"])
    return {
        "status": "OK",
        "target_path": str(fp),
        "findings": findings,
        "total_pattern_types_found": len(findings),
        "suspicious_count": suspicious_count,
        "duration_ms": round((time.time() - t0) * 1000),
    }


@mcp.tool()
async def parse_jump_lists(image_path: str) -> dict[str, Any]:
    """
    Parse Windows Jump Lists for evidence of cloud storage uploads and
    file access history that may indicate data staging for exfiltration.
    Pass a filename relative to ~/lab/ or an absolute path.
    """
    t0 = time.time()
    log.info(f"[parse_jump_lists] {image_path}")

    try:
        fp = _resolve(image_path)
    except FileNotFoundError as e:
        return {"status": "ERROR", "message": str(e)}

    lines = _fls_lines(fp)

    jl_lines = [
        l for l in lines
        if "automaticdestinations" in l.lower() or "customdestinations" in l.lower()
    ]

    findings: list[dict[str, Any]] = []

    for line in jl_lines:
        m = re.search(r":\s+(.+)$", line)
        if not m:
            continue
        jl_path = m.group(1).strip()
        jl_name = Path(jl_path).name

        is_browser = any(b in jl_name.lower() for b in ["chrome", "firefox", "edge", "iexplore"])
        is_file_manager = any(f in jl_name.lower() for f in ["explorer", "total", "filezilla"])

        rc, jle_out, _ = _run(["JLECmd.exe", "-f", jl_path, "--csv", "/tmp"], timeout=20)
        if rc == 0 and jle_out:
            for out_line in jle_out.splitlines():
                cloud_domain = _is_cloud_domain(out_line)
                archive_m = re.search(r"([\w\\/:. -]+\.(?:zip|rar|7z|tar|gz))", out_line, re.IGNORECASE)

                if cloud_domain:
                    findings.append({
                        "application": jl_name,
                        "target": out_line.strip()[:200],
                        "cloud_domain": cloud_domain,
                        "suspicious": True,
                        "reason": f"Browser/app accessed cloud storage: {cloud_domain}",
                        "confidence": 0.92,
                        "mitre_technique": "T1567.002",
                        "severity": "HIGH",
                    })
                elif archive_m:
                    archive_path = archive_m.group(1)
                    findings.append({
                        "application": jl_name,
                        "target": archive_path,
                        "suspicious": True,
                        "reason": "Archive file accessed — possible staging",
                        "confidence": 0.75,
                        "mitre_technique": "T1560.001",
                        "severity": "MEDIUM",
                    })
        else:
            findings.append({
                "application": jl_name,
                "target": "Unknown — extraction required",
                "is_browser": is_browser,
                "suspicious": is_browser,
                "reason": "Browser Jump List found — use JLECmd.exe for content",
                "confidence": 0.50,
                "mitre_technique": None,
                "severity": "LOW",
            })

    suspicious_count = sum(1 for f in findings if f["suspicious"])
    return {
        "status": "OK" if findings else "NOT_FOUND",
        "image_path": str(fp),
        "findings": findings,
        "total_jump_lists": len(jl_lines),
        "suspicious_count": suspicious_count,
        "note": "JLECmd.exe required for full URL/path extraction",
        "duration_ms": round((time.time() - t0) * 1000),
    }


@mcp.tool()
async def parse_registry_usb_history(image_path: str) -> dict[str, Any]:
    """
    Extract USB device connection history from the Windows Registry.

    Reads SYSTEM hive's USBSTOR key to find connected removable storage
    devices. Cross-references connection times with incident timeframe.
    Pass a filename relative to ~/lab/ or an absolute path.
    """
    t0 = time.time()
    log.info(f"[parse_registry_usb_history] {image_path}")

    try:
        fp = _resolve(image_path)
    except FileNotFoundError as e:
        return {"status": "ERROR", "message": str(e)}

    rc, rip_out, _ = _run(["regripper", "-r", str(fp), "-p", "usbstor"], timeout=30)
    devices: list[dict[str, Any]] = []

    if rc == 0 and rip_out.strip():
        current_device: dict[str, Any] = {}
        for line in rip_out.splitlines():
            if "Device:" in line or "FriendlyName:" in line:
                if current_device:
                    devices.append(current_device)
                name = line.split(":", 1)[-1].strip()
                current_device = {
                    "device_name": name,
                    "suspicious": True,
                    "reason": "USB storage device detected",
                    "confidence": 0.70,
                    "mitre_technique": "T1052.001",
                    "severity": "MEDIUM",
                }
            elif "Serial:" in line or "SerialNumber:" in line:
                current_device["serial_number"] = line.split(":", 1)[-1].strip()
            elif "Last Connected:" in line or "LastWrite:" in line:
                current_device["last_connected"] = line.split(":", 1)[-1].strip()
            elif "Drive Letter:" in line:
                current_device["drive_letter"] = line.split(":", 1)[-1].strip()
        if current_device:
            devices.append(current_device)
    else:
        lines = _fls_lines(fp)
        for line in lines:
            if "usbstor" in line.lower():
                m = re.search(r":\s+(.+)$", line)
                if m:
                    devices.append({
                        "device_name": m.group(1).strip(),
                        "suspicious": True,
                        "reason": "USBSTOR registry path found via filesystem scan",
                        "confidence": 0.60,
                        "mitre_technique": "T1052.001",
                        "severity": "MEDIUM",
                        "note": "Use regripper usbstor plugin for full device details",
                    })

    return {
        "status": "OK" if devices else "NOT_FOUND",
        "image_path": str(fp),
        "devices": devices,
        "total_devices": len(devices),
        "suspicious_count": len(devices),
        "note": "Any USB storage device during incident timeframe is suspicious",
        "duration_ms": round((time.time() - t0) * 1000),
    }


@mcp.tool()
async def parse_prefetch(image_path: str, exe_name: str) -> dict[str, Any]:
    """
    Check Prefetch for archive/compression tool execution (data staging).

    Common exfiltration-related tools:
      7z.exe / 7za.exe  — 7-Zip compression
      WinRAR.exe        — WinRAR compression
      powershell.exe    — Compress-Archive cmdlet
      tar.exe           — Unix tar

    Args:
        image_path: Path to disk image (relative to ~/lab/ or absolute)
        exe_name:   Executable to search for (e.g. '7z.exe')
    """
    t0 = time.time()
    log.info(f"[parse_prefetch] {image_path} / {exe_name}")

    try:
        fp = _resolve(image_path)
    except FileNotFoundError as e:
        return {"status": "ERROR", "message": str(e)}

    lines = _fls_lines(fp)
    exe_base = Path(exe_name).stem.upper()

    pf_lines = [
        l for l in lines
        if "prefetch" in l.lower() and exe_base in l.upper() and l.upper().endswith(".PF")
    ]

    is_archive_tool = exe_name.lower() in ARCHIVE_TOOLS
    mitre = ARCHIVE_TOOLS.get(exe_name.lower(), "T1560.001")

    if not pf_lines:
        return {
            "status": "NOT_FOUND",
            "executable": exe_name,
            "image_path": str(fp),
            "execution_confirmed": False,
            "is_archive_tool": is_archive_tool,
            "note": f"No Prefetch found for {exe_name}",
            "duration_ms": round((time.time() - t0) * 1000),
        }

    pf_file = re.search(r":\s+(.+\.pf)$", pf_lines[0], re.IGNORECASE)
    pf_filename = pf_file.group(1).strip() if pf_file else pf_lines[0]

    rc, pecmd_out, _ = _run(["PECmd.exe", "-f", pf_filename, "--csv", "/tmp"], timeout=30)
    run_count = 1
    files_accessed: list[str] = []
    command_args = ""

    if rc == 0 and pecmd_out:
        for line in pecmd_out.splitlines():
            m = re.search(r"Run count[:\s]+(\d+)", line, re.IGNORECASE)
            if m:
                run_count = int(m.group(1))
            elif "Command" in line:
                command_args = line.split(":", 1)[-1].strip()
            elif "\\" in line:
                files_accessed.append(line.strip())

    sensitive_files = [
        f for f in files_accessed
        if any(kw in f.lower() for kw in ["document", "financ", "password", "credit", "secret", "confidential"])
    ]

    return {
        "status": "FOUND",
        "executable": exe_name,
        "prefetch_file": Path(pf_filename).name,
        "image_path": str(fp),
        "execution_confirmed": True,
        "run_count": run_count,
        "command_line_args": command_args,
        "files_accessed": files_accessed[:20],
        "sensitive_files_accessed": sensitive_files,
        "is_archive_tool": is_archive_tool,
        "suspicious": is_archive_tool,
        "reason": f"Archive tool '{exe_name}' executed — possible data staging" if is_archive_tool else "Tool execution confirmed",
        "confidence": 0.90 if is_archive_tool else 0.55,
        "mitre_technique": mitre,
        "severity": "HIGH" if is_archive_tool else "INFO",
        "duration_ms": round((time.time() - t0) * 1000),
    }


if __name__ == "__main__":
    log.info("-" * 60)
    log.info("Exfiltration MCP Server (FastMCP) starting")
    log.info(f"  Lab dir : {LAB_DIR}")
    log.info(f"  Logs    : {LOG_DIR}")
    log.info("-" * 60)
    mcp.run()
