#!/usr/bin/env python3
from __future__ import annotations
import os
import sys
import shutil
import subprocess
from pathlib import Path
from typing import List, Optional
import logging
from bcl_umj_probe.utils.RedisDB import RedisDB
from bcl_umj_probe.utils.network_utils.ProbeInfo import ProbeInfo
import uuid
from passlib.hash import bcrypt
import asyncio

logging.basicConfig(level=logging.DEBUG)
logging.getLogger('passlib').setLevel(logging.ERROR)
logger = logging.getLogger(__name__)
prb_db = RedisDB(hostname='localhost', port='6379')
probe_utils = ProbeInfo()

PROJECT_ROOT = Path(__file__).resolve().parent
BUILD_SCRIPT = PROJECT_ROOT / "build_package.sh"
DEPENDENCIES_SCRIPT = PROJECT_ROOT / "preinstall.sh"
MAKE_CWD = PROJECT_ROOT
PROBE_DIR = PROJECT_ROOT / "bcl_umj_probe"
VENV_BIN = PROBE_DIR / "venv" / "bin"

# Uvicorn settings
UVICORN_APP = "app:api"
UVICORN_HOST = "0.0.0.0"
UVICORN_PORT = "8000"
UVICORN_WORKERS = "4"
UVICORN_LOG_LEVEL = "info"

async def probe_init():
    await prb_db.connect_db()
    ping = await prb_db.ping_db()
    logger.info(f'redis db ping result: {ping}')
    prb_id, hstnm = probe_utils.gen_probe_register_data()

    if await prb_db.get_all_data(match=f'*{hstnm}*', cnfrm=True) is False:
        probe_data=probe_utils.collect_local_stats(id=f"{prb_id}", hostname=hstnm)
        probe_data['api_key'] = bcrypt.hash(str(uuid.uuid4()))
        logger.info(f"API Key for umjiniti probe {id}: {probe_data['api_key']}. Store this is a secure location as it will not be displayed again.")
        logger.info(probe_data)
        logger.info(probe_utils.get_ifaces())
    
        if await prb_db.upload_db_data(id=f"{prb_id}", data=probe_data) is not None:
            logger.info(f'probe data for {prb_id} generated successfully')
            return True
        else:
            logger.error('Probe data generation failed')
            return False
    else:
        return 0

def require_tool(name: str) -> bool:
    if shutil.which(name):
        return True
    print(f"[!] Required tool not found on PATH: {name!r}")
    return False

def run_cmd(cmd: List[str], cwd: Optional[Path] = None, env: Optional[dict] = None) -> int:
    try:
        print(f"\n$ {' '.join(cmd)}\n")
        result = subprocess.run(cmd, cwd=str(cwd) if cwd else None, env=env)
        return result.returncode
    except KeyboardInterrupt:
        print("\n[!] Interrupted by user (Ctrl-C). Returning to menu...\n")
        return 130

def run_bash_script(script: Path, args: List[str]) -> int:
    if not script.exists():
        print(f"[!] Script not found: {script}")
        return 127
    if not require_tool("bash"):
        return 127
    return run_cmd(["bash", str(script), *args], cwd=script.parent)

def run_make_target(target: str) -> int:
    if not require_tool("make"):
        return 127
    return run_cmd(["make", target], cwd=MAKE_CWD)

def run_uvicorn_in_venv() -> int:
    """
    Run uvicorn from the venv inside bcl_umj_probe.
    Falls back to system uvicorn if venv not found.
    """
    uvicorn_path = VENV_BIN / "uvicorn"
    if uvicorn_path.exists():
        uvicorn_exec = str(uvicorn_path)
        logger.info(f"Using venv uvicorn: {uvicorn_exec}")
    elif require_tool("uvicorn"):
        uvicorn_exec = "uvicorn"
        logger.info("Using system uvicorn.")
    else:
        logger.info("Hint: install with: pip install 'uvicorn[standard]'")
        return 127

    cmd = [
        uvicorn_exec,
        UVICORN_APP,
        "--host", UVICORN_HOST,
        "--port", UVICORN_PORT,
        "--workers", UVICORN_WORKERS,
        "--log-level", UVICORN_LOG_LEVEL,
    ]
    return run_cmd(cmd, cwd=PROBE_DIR)

# ---- Menu -----------------------------------------------------------------

def ask_choice(prompt: str, valid: List[str]) -> str:
    while True:
        choice = input(prompt).strip()
        if choice in valid:
            return choice
        print(f"Please choose one of: {', '.join(valid)}")

def pause():
    input("\nPress Enter to return to the menu...")

def main() -> int:
    print(f"Project root: {PROJECT_ROOT}")

    while True:
        logger.info(
            "\n=== umjiniti Probe CLI ===\n"
            "1) Install dependencies + build package\n"
            "2) Run FastAPI app in venv (Uvicorn)\n"
            "q) Quit\n"
        )
        choice = ask_choice("Select an option: ", ["1", "2", "q"])

        match choice:
            case '1':
                logger.info("Running dependency + build scripts...")
                logger.info("""
                Installs the following dependencies on linux/unix systems:
                - tshark 
                - tcpdump 
                - gpsd 
                - gpsd-clients 
                - iputils-ping 
                - iperf3 
                - aircrack-ng 
                - libpcap-dev 
                - p0f 
                - traceroute

                    """)
                code = run_bash_script(DEPENDENCIES_SCRIPT, [])
                logger.info(f"[i] Dependency script exited with code {code}")
                code = run_bash_script(BUILD_SCRIPT, [])
                logger.info(f"[i] Build script exited with code {code}")
                pause()
            case '2':
                logger.info('Initialize Probe')
                result = asyncio.run(probe_init())
                logger.info(result)
                pause()
            case '3':
                print("\nStarting FastAPI app in venv. Press Ctrl-C to stop...\n")
                code = run_uvicorn_in_venv()
                logger.info(f"[i] Uvicorn exited with code {code}")
            case 'q':
                logger.info("Bye!")
                return 0

if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except KeyboardInterrupt:
        print("\nInterrupted. Exiting.")
        raise SystemExit(130)
