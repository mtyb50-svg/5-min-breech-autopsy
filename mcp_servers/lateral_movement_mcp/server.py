#!/usr/bin/env python3
"""
Lateral Movement Agent MCP Server — built with FastMCP
=======================================================
Tools:
  1. parse_event_logs        — authentication events (4624, 4648, 4672, 5140)
  2. parse_jump_lists        — RDP connection history via Jump Lists
  3. analyze_memory_network  — active network connections from memory dump
  4. parse_prefetch          — remote tool execution evidence

Evidence dir : ~/lab/
Logs         : ~/mcp_server/logs/lateral_movement_mcp.log
"""

import logging
import re
import subprocess
import time
from pathlib import Path
from typing import Any, Optional

from fastmcp import FastMCP

LAB_DIR = Path.home() / "lab"
LOG_DIR = Path(__file__).parent / "logs"
LOG_DIR.mkdir(parents=True, exist_ok=True)

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(message)s",
    handlers=[
        logging.FileHandler(LOG_DIR / "lateral_movement_mcp.log"),
        logging.StreamHandler(),
    ],
)
log = logging.getLogger("lateral_movement_mcp")

mcp = FastMCP(
    name="lateral-movement-mcp-server",
    instructions=(
        "Lateral movement specialist MCP server. Detects how attackers "
        "spread across networks using authentication events, RDP, SMB, "
        "WinRM, and PSExec. Evidence files must be placed in ~/lab/."
    ),
)

INTERNAL_PREFIXES = ("10.", "172.16.", "172.17.", "172.18.", "172.19.",
                     "172.20.", "172.21.", "172.22.", "172.23.", "172.24.",
                     "172.25.", "172.26.", "172.27.", "172.28.", "172.29.",
                     "172.30.", "172.31.", "192.168.", "127.")

LOGON_TYPES = {
    2: "Interactive", 3: "Network", 4: "Batch", 5: "Service",
    7: "Unlock", 8: "NetworkCleartext", 9: "NewCredentials",
    10: "RemoteInteractive (RDP)", 11: "CachedInteractive",
}

SUSPICIOUS_LOGON_TYPES = {10, 3}
ADMIN_SHARES = {"c$", "admin$", "ipc$", "sysvol", "netlogon"}

REMOTE_TOOLS = {
    "psexec.exe": "T1570",
    "psexecsvc.exe": "T1570",
    "wmic.exe": "T1021.003",
    "winrs.exe": "T1021.006",
    "powershell.exe": "T1059.001",
    "mstsc.exe": "T1021.001",
    "net.exe": "T1135",
    "net1.exe": "T1135",
}


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


def _is_internal_ip(ip: str) -> bool:
    return ip.startswith(INTERNAL_PREFIXES)


def _is_service_account(account: str) -> bool:
    low = account.lower()
    return (low.endswith("_svc") or low.endswith("$") or
            low.startswith("svc_") or "service" in low)


@mcp.tool()
async def parse_event_logs(
    image_path: str,
    event_ids: Optional[list[int]] = None,
    start_time: Optional[str] = None,
    end_time: Optional[str] = None,
) -> dict[str, Any]:
    """
    Parse Windows Event Logs for authentication and lateral movement events.

    Extracts Event IDs relevant to lateral movement:
      4624 - Successful logon
      4648 - Logon with explicit credentials
      4672 - Special privileges assigned
      5140 - Network share accessed

    Args:
        image_path: Path to disk image (relative to ~/lab/ or absolute)
        event_ids:  List of event IDs to filter (default: all lateral movement IDs)
        start_time: ISO 8601 start time filter (e.g. '2020-12-19T03:40:00Z')
        end_time:   ISO 8601 end time filter (e.g. '2020-12-19T04:30:00Z')
    """
    t0 = time.time()
    log.info(f"[parse_event_logs] {image_path}")

    try:
        fp = _resolve(image_path)
    except (FileNotFoundError, PermissionError) as e:
        return {"status": "ERROR", "message": str(e)}

    target_ids = set(event_ids) if event_ids else {4624, 4648, 4672, 5140, 4625}
    lines = _fls_lines(fp)

    evtx_lines = [l for l in lines if ".evtx" in l.lower()]
    security_evtx = [l for l in evtx_lines if "security" in l.lower()]

    events: list[dict[str, Any]] = []

    offset = _get_partition_offset(fp)
    inode_re = re.compile(r"^[dr]/.\s+(\d+)(?:-\d+)*:\s+(.+)$")

    for evtx_line in (security_evtx or evtx_lines[:5]):
        m = re.search(r":\s+(.+\.evtx)$", evtx_line, re.IGNORECASE)
        if not m:
            continue
        evtx_path = m.group(1).strip()

        # Try evtx_dump directly (clean, no shell injection risk)
        rc, evtx_out, _ = _run(["evtx_dump", evtx_path], timeout=60)

        # Fallback: extract via icat then pipe to evtx_dump
        if (rc != 0 or not evtx_out.strip()):
            inode_m = inode_re.match(evtx_line)
            if inode_m:
                icat_cmd = ["icat"]
                if offset:
                    icat_cmd += ["-o", str(offset)]
                icat_cmd += [str(fp), inode_m.group(1)]
                rc_ic, icat_bytes, _ = _run(icat_cmd, timeout=20)
                if rc_ic == 0 and icat_bytes:
                    # Write to temp file for evtx_dump
                    import tempfile, os
                    with tempfile.NamedTemporaryFile(suffix=".evtx", delete=False) as tmp:
                        tmp.write(icat_bytes.encode(errors="replace"))
                        tmp_path = tmp.name
                    try:
                        rc, evtx_out, _ = _run(["evtx_dump", tmp_path], timeout=60)
                    finally:
                        os.unlink(tmp_path)

        # Last resort: strings
        if not evtx_out or not evtx_out.strip():
            rc, evtx_out, _ = _run(["strings", "-n", "8", evtx_path], timeout=20)

        if not evtx_out:
            continue

        for line in evtx_out.splitlines():
            for eid in target_ids:
                if str(eid) in line:
                    logon_type = None
                    account = "Unknown"
                    source_ip = "Unknown"

                    lt_m = re.search(r"LogonType[>\s]+(\d+)", line)
                    if lt_m:
                        logon_type = int(lt_m.group(1))

                    acc_m = re.search(r"TargetUserName[>\s]+(\w+)", line)
                    if acc_m:
                        account = acc_m.group(1)

                    ip_m = re.search(r"IpAddress[>\s]+([\d.]+)", line)
                    if ip_m:
                        source_ip = ip_m.group(1)

                    suspicious = False
                    reason = "Authentication event"
                    confidence = 0.5
                    mitre = None
                    share_name = None

                    if eid == 4624:
                        if logon_type == 10:
                            suspicious = True
                            reason = "RDP logon (Type 10)"
                            confidence = 0.80
                            mitre = "T1021.001"
                        elif logon_type == 3:
                            suspicious = True
                            reason = "Network logon (Type 3) — possible SMB"
                            confidence = 0.65
                            mitre = "T1021.002"
                        if _is_service_account(account) and logon_type in (10, 2):
                            suspicious = True
                            reason = f"Service account '{account}' used for interactive logon"
                            confidence = 0.90
                    elif eid == 4648:
                        suspicious = True
                        reason = "Explicit credentials used (runas / lateral movement)"
                        confidence = 0.85
                        mitre = "T1021.001"
                    elif eid == 5140:
                        share_m = re.search(r"ShareName[>\s]+([\\\w.$]+)", line)
                        share_name = share_m.group(1).strip() if share_m else None
                        share_lower = (share_name or "").lower().lstrip("\\")
                        is_admin_share = share_lower in ADMIN_SHARES
                        suspicious = True
                        reason = (
                            f"Admin share accessed: {share_name} — lateral movement indicator"
                            if is_admin_share else "Network share accessed"
                        )
                        confidence = 0.85 if is_admin_share else 0.70
                        mitre = "T1021.002"

                    events.append({
                        "event_id": eid,
                        "logon_type": logon_type,
                        "logon_type_name": LOGON_TYPES.get(logon_type, "Unknown") if logon_type else None,
                        "account_name": account,
                        "source_ip": source_ip,
                        "share_name": share_name,
                        "suspicious": suspicious,
                        "reason": reason,
                        "confidence": confidence,
                        "mitre_technique": mitre,
                        "severity": "HIGH" if confidence >= 0.80 else "MEDIUM" if confidence >= 0.60 else "LOW",
                        "raw_line": line[:200],
                    })
                    break

    if not events:
        evtx_count = len(evtx_lines)
        return {
            "status": "WARNING",
            "image_path": str(fp),
            "message": (
                f"Found {evtx_count} .evtx files but could not parse content. "
                "Ensure python-evtx or evtx_dump is installed: pip install python-evtx"
            ),
            "evtx_files_found": [re.search(r":\s+(.+)$", l).group(1) for l in evtx_lines[:10] if re.search(r":\s+(.+)$", l)],
            "events": [],
            "suspicious_count": 0,
            "duration_ms": round((time.time() - t0) * 1000),
        }

    suspicious_count = sum(1 for e in events if e["suspicious"])
    return {
        "status": "OK",
        "image_path": str(fp),
        "events": events[:100],
        "total_events": len(events),
        "suspicious_count": suspicious_count,
        "event_ids_searched": sorted(target_ids),
        "time_filter": {"start": start_time, "end": end_time},
        "duration_ms": round((time.time() - t0) * 1000),
    }


@mcp.tool()
async def parse_jump_lists(image_path: str) -> dict[str, Any]:
    """
    Parse Windows Jump Lists to find recent RDP connection history.

    Jump Lists record recently accessed files and remote connections,
    making them valuable for reconstructing lateral movement via RDP.
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
        if ("automaticdestinations" in l.lower() or "customdestinations" in l.lower())
        and re.search(r":\s+.+$", l)
    ]

    findings: list[dict[str, Any]] = []

    for line in jl_lines:
        m = re.search(r":\s+(.+)$", line)
        if not m:
            continue
        jl_path = m.group(1).strip()
        jl_name = Path(jl_path).name

        is_mstsc = "mstsc" in jl_name.lower() or "rdp" in jl_name.lower()

        rc, jle_out, _ = _run(["JLECmd.exe", "-f", jl_path, "--csv", "/tmp"], timeout=20)
        if rc == 0 and jle_out:
            for out_line in jle_out.splitlines():
                ip_m = re.search(r"\b(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})\b", out_line)
                host_m = re.search(r"([\w.-]+\.(?:local|corp|internal|lan))", out_line)
                target = (ip_m.group(1) if ip_m else
                          host_m.group(1) if host_m else "Unknown")

                if target != "Unknown":
                    is_internal = _is_internal_ip(target) if ip_m else True
                    findings.append({
                        "application": "mstsc.exe" if is_mstsc else jl_name,
                        "target": target,
                        "connection_type": "RDP" if is_mstsc else "Remote Connection",
                        "is_internal_target": is_internal,
                        "suspicious": True,
                        "reason": (
                            "RDP to internal host" if is_mstsc and is_internal
                            else "RDP to external host — unusual" if is_mstsc
                            else "Remote connection via Jump List"
                        ),
                        "confidence": 0.85 if is_mstsc else 0.70,
                        "mitre_technique": "T1021.001" if is_mstsc else "T1021.002",
                        "severity": "HIGH",
                        "jump_list_file": jl_name,
                    })
        else:
            findings.append({
                "application": "mstsc.exe" if is_mstsc else "unknown",
                "target": "Unknown — extraction required",
                "connection_type": "RDP" if is_mstsc else "Unknown",
                "suspicious": is_mstsc,
                "reason": "RDP Jump List found — use JLECmd.exe for full extraction" if is_mstsc else "Jump List found",
                "confidence": 0.60 if is_mstsc else 0.40,
                "mitre_technique": "T1021.001" if is_mstsc else None,
                "severity": "MEDIUM" if is_mstsc else "LOW",
                "jump_list_file": jl_name,
            })

    suspicious_count = sum(1 for f in findings if f["suspicious"])
    return {
        "status": "OK" if findings else "NOT_FOUND",
        "image_path": str(fp),
        "findings": findings,
        "total_jump_lists": len(jl_lines),
        "suspicious_count": suspicious_count,
        "note": "JLECmd.exe required for full content extraction. Findings show file presence.",
        "duration_ms": round((time.time() - t0) * 1000),
    }


@mcp.tool()
async def analyze_memory_network(memory_path: str) -> dict[str, Any]:
    """
    Extract active network connections from a memory dump using Volatility.

    Runs windows.netscan plugin to list all TCP/UDP connections at the
    time of memory capture. Identifies lateral movement connections
    (RDP port 3389, SMB port 445, WinRM port 5985).

    Args:
        memory_path: Path to memory dump (relative to ~/lab/ or absolute)
    """
    t0 = time.time()
    log.info(f"[analyze_memory_network] {memory_path}")

    try:
        fp = _resolve(memory_path)
    except FileNotFoundError as e:
        return {"status": "ERROR", "message": str(e)}

    LATERAL_PORTS = {
        3389: ("RDP", "T1021.001"),
        445: ("SMB", "T1021.002"),
        139: ("SMB/NetBIOS", "T1021.002"),
        5985: ("WinRM HTTP", "T1021.006"),
        5986: ("WinRM HTTPS", "T1021.006"),
        135: ("RPC/DCOM", "T1021.003"),
    }

    rc, vol_out, vol_err = _run(
        ["vol", "-f", str(fp), "windows.netscan"],
        timeout=120,
    )

    connections: list[dict[str, Any]] = []

    if rc == 0 and vol_out.strip():
        for line in vol_out.splitlines()[1:]:
            parts = line.split()
            if len(parts) < 5:
                continue

            local_addr = parts[0] if parts else ""
            remote_addr = parts[2] if len(parts) > 2 else ""
            state = parts[3] if len(parts) > 3 else ""
            process = parts[-1] if parts else ""

            local_ip = local_addr.split(":")[0] if ":" in local_addr else local_addr
            local_port_str = local_addr.split(":")[-1] if ":" in local_addr else "0"
            remote_ip = remote_addr.split(":")[0] if ":" in remote_addr else remote_addr
            remote_port_str = remote_addr.split(":")[-1] if ":" in remote_addr else "0"

            try:
                local_port = int(local_port_str)
                remote_port = int(remote_port_str)
            except ValueError:
                continue

            lateral_info = LATERAL_PORTS.get(local_port) or LATERAL_PORTS.get(remote_port)
            is_external = not _is_internal_ip(remote_ip) and remote_ip not in ("0.0.0.0", "*", "::")

            suspicious = bool(lateral_info) or is_external
            if lateral_info:
                proto_name, mitre = lateral_info
                reason = f"{proto_name} connection detected"
                confidence = 0.85
            elif is_external:
                proto_name = "Unknown"
                mitre = "T1041"
                reason = "Connection to external IP"
                confidence = 0.80
            else:
                proto_name = "Internal"
                mitre = None
                reason = "Internal network connection"
                confidence = 0.30

            connections.append({
                "local_ip": local_ip,
                "local_port": local_port,
                "remote_ip": remote_ip,
                "remote_port": remote_port,
                "state": state,
                "process": process,
                "protocol_type": proto_name,
                "is_external": is_external,
                "suspicious": suspicious,
                "reason": reason,
                "confidence": confidence,
                "mitre_technique": mitre,
                "severity": "HIGH" if confidence >= 0.80 else "MEDIUM",
            })
    else:
        return {
            "status": "WARNING",
            "memory_path": str(fp),
            "message": (
                "Volatility could not parse memory dump. "
                f"Error: {vol_err[:300] if vol_err else 'Unknown'}. "
                "Ensure volatility3 is installed: pip install volatility3"
            ),
            "connections": [],
            "suspicious_count": 0,
            "duration_ms": round((time.time() - t0) * 1000),
        }

    suspicious_count = sum(1 for c in connections if c["suspicious"])
    lateral_connections = [c for c in connections if c.get("protocol_type") in ("RDP", "SMB", "WinRM HTTP", "WinRM HTTPS")]

    return {
        "status": "OK",
        "memory_path": str(fp),
        "connections": connections[:100],
        "total_connections": len(connections),
        "suspicious_count": suspicious_count,
        "lateral_movement_connections": lateral_connections[:20],
        "lateral_movement_count": len(lateral_connections),
        "duration_ms": round((time.time() - t0) * 1000),
    }


@mcp.tool()
async def parse_prefetch(image_path: str, exe_name: str) -> dict[str, Any]:
    """
    Check Prefetch files for evidence of remote access tool execution.

    Common tools indicating lateral movement:
      mstsc.exe    — Remote Desktop client
      psexec.exe   — Remote execution tool
      net.exe      — Network commands
      powershell.exe — Often used for lateral movement

    Args:
        image_path: Path to disk image (relative to ~/lab/ or absolute)
        exe_name:   Executable name to search for (e.g. 'psexec.exe')
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

    mitre = REMOTE_TOOLS.get(exe_name.lower(), "T1570")
    is_remote_tool = exe_name.lower() in REMOTE_TOOLS

    if not pf_lines:
        return {
            "status": "NOT_FOUND",
            "executable": exe_name,
            "image_path": str(fp),
            "execution_confirmed": False,
            "note": f"No Prefetch found for {exe_name}",
            "is_remote_tool": is_remote_tool,
            "duration_ms": round((time.time() - t0) * 1000),
        }

    pf_file = re.search(r":\s+(.+\.pf)$", pf_lines[0], re.IGNORECASE)
    pf_filename = pf_file.group(1).strip() if pf_file else pf_lines[0]

    rc, pecmd_out, _ = _run(["PECmd.exe", "-f", pf_filename, "--csv", "/tmp"], timeout=30)
    run_count = 1
    files_accessed: list[str] = []

    if rc == 0 and pecmd_out:
        for line in pecmd_out.splitlines():
            m = re.search(r"Run count[:\s]+(\d+)", line, re.IGNORECASE)
            if m:
                run_count = int(m.group(1))
            elif "\\" in line and any(line.lower().endswith(e) for e in [".exe", ".dll", ".bat"]):
                files_accessed.append(line.strip())

    remote_path_accessed = [
        f for f in files_accessed
        if re.search(r"\\\\[\d.]+\\|\\\\[a-zA-Z][\w.-]+\\", f)
    ]

    return {
        "status": "FOUND",
        "executable": exe_name,
        "prefetch_file": Path(pf_filename).name,
        "image_path": str(fp),
        "execution_confirmed": True,
        "run_count": run_count,
        "files_accessed": files_accessed[:20],
        "remote_paths_accessed": remote_path_accessed,
        "is_remote_tool": is_remote_tool,
        "suspicious": is_remote_tool,
        "reason": f"Remote access tool '{exe_name}' was executed" if is_remote_tool else "Tool execution confirmed",
        "confidence": 0.95 if is_remote_tool else 0.60,
        "mitre_technique": mitre,
        "severity": "HIGH" if is_remote_tool else "INFO",
        "duration_ms": round((time.time() - t0) * 1000),
    }


if __name__ == "__main__":
    log.info("-" * 60)
    log.info("Lateral Movement MCP Server (FastMCP) starting")
    log.info(f"  Lab dir : {LAB_DIR}")
    log.info(f"  Logs    : {LOG_DIR}")
    log.info("-" * 60)
    mcp.run()
