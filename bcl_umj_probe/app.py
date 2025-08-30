from init_app import (api, mcp)
from typing import Callable
from utils.network_utils.NetworkInfo import NetworkInfo
from utils.network_utils.NetworkDiscovery import NetworkDiscovery
from utils.network_utils.NetworkTest import NetworkTest
from utils.Probe import Probe
from utils.NetUtil import NetUtil
import json
import os
from pathlib import Path
import logging
import inspect
import aiohttp
from utils.RedisDB import RedisDB
import asyncio
from utils.Probe import Probe
from fastapi import FastAPI, Header, requests
import httpx

from pydantic import BaseModel

class Init(BaseModel):
    api_key: str | None = None
    usr: str | None = None
    url: str | None = None
    site: str | None = None
    enroll: bool

logging.basicConfig(level=logging.DEBUG)
logging.getLogger('passlib').setLevel(logging.ERROR)
logger = logging.getLogger(__name__)

network_info = NetworkInfo()
net_discovery = NetworkDiscovery()
net_test = NetworkTest()
probe_utils = Probe()
client_session = aiohttp.ClientSession()
net_utils = NetUtil()

# Probe network monitoring & survey functions
action_map: dict[str, Callable[[dict], object]] = {
    "dscv" : net_utils.full_discovery,
    "dscv_host": net_utils.net_host_scan,
    "spdtst" : net_test.start_iperf,
    "trcrt_dns" : net_test.traceroute_dns,
    "trcrt_syn" : net_test.traceroute_syn,
    "trcrt_udp" : net_test.traceroute_udp,
    "lcldt": probe_utils.collect_local_stats,
    "wifi_srvy_on": net_utils.start_survey,
    "wifi_srvy_off": net_utils.stop_survey,
    "wifi_srvy_rprt": net_utils.generate_report,   
    "wifi_srvy_json": net_utils.get_survey_json,
}

async def _make_http_request(cmd: str, url: str, payload: dict = {}, headers: dict = {}):
    async with httpx.AsyncClient() as client:
        match cmd:
            case 'p':
                resp = await client.post(
                    url,
                    json=payload,
                    headers=headers
                )
                return resp
            case 'g':
                resp = await client.get(
                    url,
                    headers=headers
                )
                return resp


@api.get("/api/status")
def status():
    return {"status": "ok"}

@api.post("/api/init")
async def init(init_data: Init):
    async def enrollment(payload={}):
        headers = {'X-UMJ-WFLW-API-KEY': init_data.api_key}
        enroll_url=f"{init_data.url}?usr={init_data.usr}&site={init_data.site}"

        resp_data = await _make_http_request(cmd='g', url=init_data.url, headers=headers)
        if resp_data.status_code == 200:
            return resp_data.cookies.get('access_token')
        
    prb_db = RedisDB(hostname='localhost', port='6369')
    await prb_db.connect_db()

    # Set probe info data
    prb_id, hstnm = probe_utils.gen_probe_register_data()

    if init_data.enroll is False or init_data.api_key and init_data.usr and init_data.url and init_data.site is None or "".strip():
        return 400
    else:
        probe_data = await prb_db.get_all_data(match=f'*{hstnm}*')

        if probe_data.items():
            await enrollment(payload=probe_data)     

@mcp.tool
def query_database(query: str) -> dict:
    """Run a database query"""
    return {"result": "data"}

# Run with: uvicorn app:api --host 0.0.0.0 --port 8000

# Install uvicorn with standard extras for better performance: pip install 'uvicorn[standard]'

# Run with multiple workers for better concurrency: uvicorn app:app --host 0.0.0.0 --port 8000 --workers 4

# Enable detailed logging for monitoring: uvicorn app:app --host 0.0.0.0 --port 8000 --log-level info