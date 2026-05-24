#!/usr/bin/env python3
"""
Credential Access Agent MCP Server — built with FastMCP
========================================================
Tools:
  1. analyze_memory_processes    — detect credential dumping tools in memory
  2. parse_event_logs            — authentication failures (4625, 4771, 4776)
  3. search_password_files       — find password-containing files on disk
  4. analyze_browser_credentials — check browser saved password databases
  5. parse_prefetch              — credential tool execution validation
  6. analyze_sam_database        — SAM hive access and local password hashes

Evidence dir : ~/lab/
Logs         : ~/mcp_server/logs/credential_access_mcp.log
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
        logging.FileHandler(LOG_DIR / "credential_access_mcp.log"),
        logging.StreamHandler(),
    ],
)
log = logging.getLogger("credential_access_mcp")

mcp = FastMCP(
    name="credential-access-mcp-server",
    instructions=(
        "Credential access specialist MCP server. Detects LSASS dumps, "
        "Mimikatz/ProcDump usage, password file access, browser credential "
        "theft, SAM database access, and brute-force attacks. "
        "Evidence files must be placed in ~/lab/."
    ),
)

CREDENTIAL_TOOLS = {
    "mimikatz.exe": ("Mimikatz credential dumper", "T1003.001", "CRITICAL"),
    "procdump.exe": ("ProcDump — used to dump LSASS", "T1003.001", "CRITICAL"),
    "procdump64.exe": ("ProcDump64 — used to dump LSASS", "T1003.001", "CRITICAL"),
    "lazagne.exe": ("LaZagne password recovery tool", "T1555", "CRITICAL"),
    "pwdump.exe": ("PwDump SAM dumper", "T1003.002", "CRITICAL"),
    "fgdump.exe": ("FgDump credential dumper", "T1003.001", "CRITICAL"),
    "gsecdump.exe": ("GSecdump credential tool", "T1003.001", "CRITICAL"),
    "wce.exe": ("Windows Credential Editor", "T1003.001", "CRITICAL"),
    "secretsdump.py": ("Impacket secretsdump", "T1003.002", "CRITICAL"),
    "ntdsutil.exe": ("NTDS extraction via ntdsutil", "T1003.003", "CRITICAL"),
}

PASSWORD_FILENAMES = [
    "passwords.txt", "pass.txt", "credentials.txt", "creds.txt",
    "logins.txt", "accounts.txt", "login.txt", "secrets.txt",
    "passwords.csv", "creds.csv", "logins.csv", "accounts.csv",
    "passwords.xlsx", "creds.xlsx", "logins.xlsx",
    "passwords.docx", "passwords.doc",
    "lsass.dmp", "lsass.zip", "memory.dmp",
    ".kdbx",
]

BROWSER_DB_PATHS = {
    "Chrome": "AppData\\Local\\Google\\Chrome\\User Data\\Default\\Login Data",
    "Firefox": "AppData\\Roaming\\Mozilla\\Firefox\\Profiles",
    "Edge": "AppData\\Local\\Microsoft\\Edge\\User Data\\Default\\Login Data",
    "IE": "AppData\\Roaming\\Microsoft\\Windows\\IECompatCache",
}


def _run(cmd: list[str], timeout: int = 60) -> tuple[int, str, str]:
    try:
        r = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout)
        return r.returncode, r.stdout, r.stderr
    except subprocess.TimeoutExpired:
        return -1, "", f"Timed out after {timeout}s: {' '.join(cmd)}"
    except FileNotFoundError:
        return -1, "", f"Tool not found: {cmd[0]}"


def _run_bytes(cmd: list[str], timeout: int = 60) -> tuple[int, bytes, bytes]:
    try:
        r = subprocess.run(cmd, capture_output=True, text=False, timeout=timeout)
        return r.returncode, r.stdout, r.stderr
    except subprocess.TimeoutExpired:
        return -1, b"", f"Timed out after {timeout}s: {' '.join(cmd)}".encode()
    except FileNotFoundError:
        return -1, b"", f"Tool not found: {cmd[0]}".encode()


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


@mcp.tool()
async def analyze_memory_processes(memory_path: str) -> dict[str, Any]:
    """
    List all processes from memory dump and detect credential dumping tools.

    Uses Volatility windows.pslist and malfind to identify:
      - Mimikatz, ProcDump, LaZagne, pwdump in running process list
      - LSASS access patterns
      - Injected code in processes

    Args:
        memory_path: Path to memory dump (relative to ~/lab/ or absolute)
    """
    t0 = time.time()
    log.info(f"[analyze_memory_processes] {memory_path}")

    try:
        fp = _resolve(memory_path)
    except FileNotFoundError as e:
        return {"status": "ERROR", "message": str(e)}

    rc, vol_out, vol_err = _run(["vol", "-f", str(fp), "windows.pslist"], timeout=120)

    processes: list[dict[str, Any]] = []
    credential_tools_found: list[dict[str, Any]] = []

    if rc == 0 and vol_out.strip():
        for line in vol_out.splitlines()[1:]:
            parts = line.split()
            if len(parts) < 3:
                continue

            pid_str = parts[0]
            ppid_str = parts[1] if len(parts) > 1 else "0"
            proc_name = parts[2] if len(parts) > 2 else "Unknown"

            try:
                pid = int(pid_str)
                ppid = int(ppid_str)
            except ValueError:
                continue

            is_cred_tool = proc_name.lower() in CREDENTIAL_TOOLS
            is_lsass = proc_name.lower() == "lsass.exe"

            if is_cred_tool:
                tool_desc, mitre, severity = CREDENTIAL_TOOLS[proc_name.lower()]
                cred_entry = {
                    "pid": pid,
                    "name": proc_name,
                    "ppid": ppid,
                    "description": tool_desc,
                    "suspicious": True,
                    "reason": f"Credential dumping tool detected: {proc_name}",
                    "confidence": 1.0,
                    "mitre_technique": mitre,
                    "severity": severity,
                }
                processes.append(cred_entry)
                credential_tools_found.append(cred_entry)
            elif is_lsass:
                processes.append({
                    "pid": pid,
                    "name": proc_name,
                    "ppid": ppid,
                    "suspicious": False,
                    "reason": "LSASS process (target of credential dumping tools)",
                    "confidence": 0.10,
                    "note": "Check if any credential tools have handles to this process",
                    "severity": "INFO",
                })

        rc2, malfind_out, _ = _run(["vol", "-f", str(fp), "windows.malfind"], timeout=120)
        if rc2 == 0 and malfind_out.strip():
            for line in malfind_out.splitlines():
                if "lsass" in line.lower() or "injected" in line.lower():
                    processes.append({
                        "pid": 0,
                        "name": "Injected Code",
                        "ppid": 0,
                        "suspicious": True,
                        "reason": "Injected code detected (possible credential dumper)",
                        "raw_line": line[:200],
                        "confidence": 0.85,
                        "mitre_technique": "T1055",
                        "severity": "HIGH",
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
            "processes": [],
            "credential_tools_found": [],
            "suspicious_count": 0,
            "duration_ms": round((time.time() - t0) * 1000),
        }

    suspicious_count = sum(1 for p in processes if p.get("suspicious"))
    return {
        "status": "OK",
        "memory_path": str(fp),
        "processes": processes[:50],
        "credential_tools_found": credential_tools_found,
        "suspicious_count": suspicious_count,
        "lsass_dump_detected": any(p["name"].lower() in ("procdump.exe", "procdump64.exe", "mimikatz.exe")
                                    for p in credential_tools_found),
        "duration_ms": round((time.time() - t0) * 1000),
    }


@mcp.tool()
async def parse_event_logs(
    image_path: str,
    event_ids: Optional[list[int]] = None,
    start_time: Optional[str] = None,
) -> dict[str, Any]:
    """
    Parse Windows Event Logs for authentication failure and credential attack events.

    Targets:
      4625 - Failed logon (brute force / password guessing)
      4771 - Kerberos pre-auth failed
      4776 - Credential validation failed
      4768 - Kerberos ticket requested
      4769 - Kerberos service ticket requested

    Args:
        image_path:  Path to disk image (relative to ~/lab/ or absolute)
        event_ids:   List of event IDs to filter (default: credential attack IDs)
        start_time:  ISO 8601 start filter
    """
    t0 = time.time()
    log.info(f"[parse_event_logs] {image_path}")

    try:
        fp = _resolve(image_path)
    except FileNotFoundError as e:
        return {"status": "ERROR", "message": str(e)}

    target_ids = set(event_ids) if event_ids else {4625, 4771, 4776, 4768, 4769}
    lines = _fls_lines(fp)

    evtx_lines = [l for l in lines if ".evtx" in l.lower()]
    security_evtx = [l for l in evtx_lines if "security" in l.lower()]

    events: list[dict[str, Any]] = []
    failure_counts: dict[str, dict[str, int]] = {}

    for evtx_line in (security_evtx or evtx_lines[:5]):
        m = re.search(r":\s+(.+\.evtx)$", evtx_line, re.IGNORECASE)
        if not m:
            continue
        evtx_path = m.group(1).strip()

        rc, evtx_out, _ = _run(["strings", "-n", "8", evtx_path], timeout=20)
        if not evtx_out:
            continue

        for line in evtx_out.splitlines():
            for eid in target_ids:
                if str(eid) not in line:
                    continue

                account = "Unknown"
                source_ip = "Unknown"
                failure_reason = "Unknown"

                acc_m = re.search(r"(?:TargetUserName|AccountName)[>\s]+(\w+)", line)
                if acc_m:
                    account = acc_m.group(1)

                ip_m = re.search(r"IpAddress[>\s]+([\d.]+)", line)
                if ip_m:
                    source_ip = ip_m.group(1)

                key = f"{source_ip}:{account}"
                if key not in failure_counts:
                    failure_counts[key] = {"count": 0, "event_id": eid}
                failure_counts[key]["count"] += 1

                events.append({
                    "event_id": eid,
                    "account_name": account,
                    "source_ip": source_ip,
                    "failure_reason": failure_reason,
                    "suspicious": False,
                    "reason": "Authentication failure",
                    "confidence": 0.30,
                    "mitre_technique": None,
                    "severity": "LOW",
                })
                break

    brute_force_detected: list[dict[str, Any]] = []
    spraying_detected: list[dict[str, Any]] = []

    by_source_ip: dict[str, dict[str, int]] = {}
    for key, info in failure_counts.items():
        source_ip, account = key.split(":", 1)
        if source_ip not in by_source_ip:
            by_source_ip[source_ip] = {}
        by_source_ip[source_ip][account] = info["count"]

    for source_ip, accounts in by_source_ip.items():
        total_attempts = sum(accounts.values())
        unique_accounts = len(accounts)

        if total_attempts >= 10 and unique_accounts == 1:
            target_account = list(accounts.keys())[0]
            brute_force_detected.append({
                "type": "brute_force",
                "source_ip": source_ip,
                "target_account": target_account,
                "attempt_count": total_attempts,
                "suspicious": True,
                "reason": f"Brute force: {total_attempts} failed attempts on '{target_account}'",
                "confidence": 0.95 if total_attempts > 50 else 0.85,
                "mitre_technique": "T1110.001",
                "severity": "HIGH",
            })
        elif unique_accounts >= 10 and (total_attempts / unique_accounts) <= 3:
            spraying_detected.append({
                "type": "password_spraying",
                "source_ip": source_ip,
                "accounts_targeted": unique_accounts,
                "total_attempts": total_attempts,
                "suspicious": True,
                "reason": f"Password spraying: {total_attempts} attempts across {unique_accounts} accounts",
                "confidence": 0.90,
                "mitre_technique": "T1110.003",
                "severity": "HIGH",
            })

    if not events:
        return {
            "status": "WARNING",
            "image_path": str(fp),
            "message": "Could not parse event logs. Ensure python-evtx is installed.",
            "evtx_files_found": len(evtx_lines),
            "events": [],
            "brute_force_detected": [],
            "spraying_detected": [],
            "duration_ms": round((time.time() - t0) * 1000),
        }

    return {
        "status": "OK",
        "image_path": str(fp),
        "events": events[:100],
        "total_failure_events": len(events),
        "brute_force_detected": brute_force_detected,
        "spraying_detected": spraying_detected,
        "attack_patterns_found": len(brute_force_detected) + len(spraying_detected),
        "duration_ms": round((time.time() - t0) * 1000),
    }


@mcp.tool()
async def search_password_files(image_path: str) -> dict[str, Any]:
    """
    Search for files likely to contain credentials on the disk image.

    Scans for common password file names (passwords.txt, creds.xlsx, etc.)
    and LSASS memory dumps. Uses fls for file system enumeration.
    Pass a filename relative to ~/lab/ or an absolute path.
    """
    t0 = time.time()
    log.info(f"[search_password_files] {image_path}")

    try:
        fp = _resolve(image_path)
    except FileNotFoundError as e:
        return {"status": "ERROR", "message": str(e)}

    lines = _fls_lines(fp)
    findings: list[dict[str, Any]] = []

    for line in lines:
        m = re.search(r":\s+(.+)$", line)
        if not m:
            continue
        file_path = m.group(1).strip()
        file_name = Path(file_path).name.lower()

        matched_name = next(
            (pf for pf in PASSWORD_FILENAMES if pf.lower() == file_name or (pf.startswith(".") and file_name.endswith(pf.lower()))),
            None
        )

        if matched_name:
            is_lsass = "lsass" in file_name
            is_kdbx = file_name.endswith(".kdbx")
            is_dump = file_name.endswith(".dmp")

            findings.append({
                "file_path": file_path,
                "file_name": Path(file_path).name,
                "match_reason": matched_name,
                "is_lsass_dump": is_lsass,
                "is_password_manager": is_kdbx,
                "is_memory_dump": is_dump,
                "suspicious": True,
                "reason": (
                    "LSASS memory dump — contains credential hashes" if is_lsass
                    else "Password manager database" if is_kdbx
                    else "File name indicates credential storage"
                ),
                "confidence": 1.0 if is_lsass else 0.90 if is_kdbx else 0.85,
                "mitre_technique": (
                    "T1003.001" if is_lsass
                    else "T1555" if is_kdbx
                    else "T1552.001"
                ),
                "severity": "CRITICAL" if is_lsass else "HIGH",
            })
        else:
            if any(kw in file_name for kw in ["password", "passwd", "cred", "login", "secret"]):
                if any(file_name.endswith(e) for e in [".txt", ".csv", ".xlsx", ".xls", ".pdf", ".doc", ".docx"]):
                    findings.append({
                        "file_path": file_path,
                        "file_name": Path(file_path).name,
                        "match_reason": "Keyword match in filename",
                        "suspicious": True,
                        "reason": "Filename contains credential-related keywords",
                        "confidence": 0.75,
                        "mitre_technique": "T1552.001",
                        "severity": "MEDIUM",
                    })

    suspicious_count = sum(1 for f in findings if f["suspicious"])
    critical_count = sum(1 for f in findings if f.get("severity") == "CRITICAL")

    return {
        "status": "OK" if findings else "NOT_FOUND",
        "image_path": str(fp),
        "findings": findings,
        "total_files_found": len(findings),
        "suspicious_count": suspicious_count,
        "critical_count": critical_count,
        "lsass_dumps_found": [f for f in findings if f.get("is_lsass_dump")],
        "duration_ms": round((time.time() - t0) * 1000),
    }


@mcp.tool()
async def analyze_browser_credentials(image_path: str) -> dict[str, Any]:
    """
    Check if browser saved password databases were accessed or stolen.

    Scans for Chrome Login Data, Firefox logins.json, and Edge Login Data
    SQLite databases. Their presence or access during incident indicates
    browser credential theft.
    Pass a filename relative to ~/lab/ or an absolute path.
    """
    t0 = time.time()
    log.info(f"[analyze_browser_credentials] {image_path}")

    try:
        fp = _resolve(image_path)
    except (FileNotFoundError, PermissionError) as e:
        return {"status": "ERROR", "message": str(e)}

    lines = _fls_lines(fp)
    browsers: list[dict[str, Any]] = []

    browser_patterns = {
        "Google Chrome": ["login data", "chrome"],
        "Mozilla Firefox": ["logins.json", "firefox"],
        "Microsoft Edge": ["login data", "edge"],
        "Internet Explorer": ["iecompatcache", "iexplore"],
    }

    offset = _get_partition_offset(fp)
    inode_re = re.compile(r"^[dr]/.\s+(\d+)(?:-\d+)*:\s+(.+)$")

    for browser_name, patterns in browser_patterns.items():
        matched_lines = [
            l for l in lines
            if all(p in l.lower() for p in patterns[:1]) and
            (len(patterns) < 2 or patterns[1] in l.lower())
        ]

        if matched_lines:
            db_paths = []
            extracted_credentials: list[dict[str, str]] = []
            credential_count = 0

            for ml in matched_lines[:3]:
                m = re.search(r":\s+(.+)$", ml)
                if m:
                    db_paths.append(m.group(1).strip())

            inode_m = inode_re.match(matched_lines[0])
            if inode_m:
                inode = inode_m.group(1)
                icat_cmd = ["icat"]
                if offset:
                    icat_cmd += ["-o", str(offset)]
                icat_cmd += [str(fp), inode]

                rc_ic, db_bytes, _ = _run_bytes(icat_cmd, timeout=20)
                if rc_ic == 0 and db_bytes:
                    import tempfile, os, json
                    
                    if "logins.json" in matched_lines[0].lower():
                        try:
                            data = json.loads(db_bytes.decode(errors="replace"))
                            logins_list = data.get("logins", [])
                            credential_count = len(logins_list)
                            for entry in logins_list[:20]:
                                extracted_credentials.append({
                                    "origin_url": entry.get("hostname", ""),
                                    "username": entry.get("usernameField", "") or entry.get("encryptedUsername", "")[:20]
                                })
                        except Exception as e:
                            log.error(f"Error parsing Firefox logins.json: {e}")
                    else:
                        with tempfile.NamedTemporaryFile(suffix=".db", delete=False) as tmp:
                            tmp.write(db_bytes)
                            tmp_path = tmp.name
                        try:
                            rc_cnt, sql_cnt, _ = _run(["sqlite3", tmp_path, "SELECT COUNT(*) FROM logins;"], timeout=10)
                            if rc_cnt == 0 and sql_cnt.strip().isdigit():
                                credential_count = int(sql_cnt.strip())

                            rc_sql, sql_out, _ = _run(
                                ["sqlite3", tmp_path, "SELECT origin_url, username_value FROM logins LIMIT 20;"],
                                timeout=10
                            )
                            if rc_sql == 0:
                                for line in sql_out.splitlines():
                                    if "|" in line:
                                        parts = line.split("|", 1)
                                        url = parts[0].strip()
                                        username = parts[1].strip() if len(parts) > 1 else ""
                                        if url or username:
                                            extracted_credentials.append({
                                                "origin_url": url,
                                                "username": username
                                            })
                        except Exception as e:
                            log.error(f"Error querying SQLite DB: {e}")
                        finally:
                            try:
                                os.unlink(tmp_path)
                            except OSError:
                                pass

            browsers.append({
                "browser": browser_name,
                "database_paths": db_paths,
                "credential_count": credential_count,
                "extracted_credentials": extracted_credentials,
                "suspicious": True,
                "reason": f"{browser_name} credential database found — may have been accessed/stolen",
                "confidence": 0.85,
                "mitre_technique": "T1555.003",
                "severity": "HIGH",
                "note": "Use sqlite3 to extract saved credentials: SELECT origin_url, username_value FROM logins",
            })

    return {
        "status": "OK" if browsers else "NOT_FOUND",
        "image_path": str(fp),
        "browsers": browsers,
        "total_browsers_found": len(browsers),
        "suspicious_count": len(browsers),
        "note": "Browser presence alone is not conclusive — check access timestamps and tool execution",
        "duration_ms": round((time.time() - t0) * 1000),
    }


@mcp.tool()
async def parse_prefetch(image_path: str, exe_name: str) -> dict[str, Any]:
    """
    Validate execution of credential dumping tools via Prefetch files.

    Key tools to check:
      mimikatz.exe   — Most common credential dumper (CRITICAL)
      procdump64.exe — ProcDump LSASS dump (CRITICAL)
      lazagne.exe    — Multi-platform credential recovery (CRITICAL)
      pwdump.exe     — SAM hash dumper (CRITICAL)

    Args:
        image_path: Path to disk image (relative to ~/lab/ or absolute)
        exe_name:   Tool name to search for (e.g. 'mimikatz.exe')
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

    is_cred_tool = exe_name.lower() in CREDENTIAL_TOOLS
    if is_cred_tool:
        tool_desc, mitre, severity = CREDENTIAL_TOOLS[exe_name.lower()]
    else:
        tool_desc, mitre, severity = "Unknown tool", None, "INFO"

    if not pf_lines:
        return {
            "status": "NOT_FOUND",
            "executable": exe_name,
            "image_path": str(fp),
            "execution_confirmed": False,
            "is_credential_tool": is_cred_tool,
            "note": f"No Prefetch found for {exe_name}. May not have run or was cleaned up.",
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
            elif "lsass" in line.lower() or "sam" in line.lower() or "security" in line.lower():
                files_accessed.append(line.strip())

    return {
        "status": "FOUND",
        "executable": exe_name,
        "prefetch_file": Path(pf_filename).name,
        "image_path": str(fp),
        "execution_confirmed": True,
        "run_count": run_count,
        "lsass_related_files": files_accessed[:10],
        "is_credential_tool": is_cred_tool,
        "tool_description": tool_desc,
        "suspicious": is_cred_tool,
        "reason": f"CONFIRMED: {tool_desc} was executed" if is_cred_tool else "Tool execution confirmed",
        "confidence": 1.0 if is_cred_tool else 0.60,
        "mitre_technique": mitre,
        "severity": severity,
        "duration_ms": round((time.time() - t0) * 1000),
    }


@mcp.tool()
async def analyze_sam_database(image_path: str) -> dict[str, Any]:
    """
    Check if the SAM database was accessed and extract local account hashes.

    Uses RegRipper to parse the SAM registry hive. The SAM database
    contains local account names and NTLM password hashes. Access
    indicates credential theft attempt.
    Pass a filename relative to ~/lab/ or an absolute path.
    """
    t0 = time.time()
    log.info(f"[analyze_sam_database] {image_path}")

    try:
        fp = _resolve(image_path)
    except FileNotFoundError as e:
        return {"status": "ERROR", "message": str(e)}

    lines = _fls_lines(fp)

    sam_lines = [l for l in lines if re.search(r"/config/sam$|\\config\\sam$", l, re.IGNORECASE)]

    if not sam_lines:
        return {
            "status": "NOT_FOUND",
            "image_path": str(fp),
            "sam_found": False,
            "message": "SAM hive not found in filesystem listing",
            "duration_ms": round((time.time() - t0) * 1000),
        }

    sam_path_m = re.search(r":\s+(.+)$", sam_lines[0])
    sam_path = sam_path_m.group(1).strip() if sam_path_m else "Unknown"

    rc, rip_out, _ = _run(["regripper", "-r", sam_path, "-p", "samparse"], timeout=30)

    accounts: list[dict[str, Any]] = []

    if rc == 0 and rip_out.strip():
        current_account: dict[str, Any] = {}
        for line in rip_out.splitlines():
            if "Username:" in line or "User:" in line:
                if current_account:
                    accounts.append(current_account)
                username = line.split(":", 1)[-1].strip()
                current_account = {
                    "username": username,
                    "hash_type": "NTLM",
                }
            elif "RID:" in line:
                current_account["rid"] = line.split(":", 1)[-1].strip()
            elif "Hash" in line or "LM:" in line or "NTLM:" in line:
                current_account["password_hash"] = line.split(":", 1)[-1].strip()
            elif "Account Disabled" in line:
                current_account["enabled"] = "disabled" not in line.lower()
        if current_account:
            accounts.append(current_account)

    has_admin = any(
        a.get("username", "").lower() in ("administrator", "admin")
        for a in accounts
    )
    has_hash = any("password_hash" in a for a in accounts)

    return {
        "status": "OK",
        "image_path": str(fp),
        "sam_path": sam_path,
        "sam_found": True,
        "sam_accessible": rc == 0,
        "accounts_found": accounts[:20],
        "account_count": len(accounts),
        "administrator_account_found": has_admin,
        "hashes_extracted": has_hash,
        "suspicious": True,
        "reason": (
            "SAM database accessible — local password hashes exposed"
            if rc == 0 else "SAM database found on disk — presence confirmed"
        ),
        "confidence": 0.95 if has_hash else 0.70,
        "mitre_technique": "T1003.002",
        "severity": "CRITICAL" if has_hash else "HIGH",
        "note": (
            "NTLM hashes can be cracked offline or used in Pass-the-Hash attacks. "
            "Combine with SYSTEM hive for full extraction."
        ),
        "duration_ms": round((time.time() - t0) * 1000),
    }


if __name__ == "__main__":
    log.info("-" * 60)
    log.info("Credential Access MCP Server (FastMCP) starting")
    log.info(f"  Lab dir : {LAB_DIR}")
    log.info(f"  Logs    : {LOG_DIR}")
    log.info("-" * 60)
    mcp.run()
