from init_app import (api, logger, validate_api_key)
from typing import Callable
from utils.network_utils.NetworkInfo import NetworkInfo
from utils.network_utils.NetworkDiscovery import NetworkDiscovery
from utils.network_utils.NetworkTest import NetworkTest
from utils.Probe import Probe
from utils.NetUtil import NetUtil
from utils.RedisDB import RedisDB
import httpx
from fastmcp import FastMCP
from fastapi import FastAPI, Depends
from pydantic import BaseModel
import uuid
from passlib.hash import bcrypt
from httpx import Cookies

class Init(BaseModel):
    api_key: str | None = None
    usr: str | None = None
    url: str | None = None
    site: str | None = None
    enroll: bool

class ToolCall(BaseModel):
    action: str | None = None
    params: dict | None = None

network_info = NetworkInfo()
net_discovery = NetworkDiscovery()
net_test = NetworkTest()
probe_utils = Probe()
net_utils = NetUtil(interface='')
prb_db = RedisDB(hostname='localhost', port='6379')

prb_action_map: dict[str, Callable[[dict], object]] = {
    "lcldt": probe_utils.collect_local_stats,
    "rgrdt": probe_utils.gen_probe_register_data
}

dscv_action_map: dict[str, Callable[[dict], object]] = {
    "dscv_full" : net_utils.full_discovery,
    "scan_ack": net_discovery.scan_ack,
    "scan_ip": net_discovery.scan_ip,
    "scan_xmas": net_discovery.scan_xmas,
    "dscv_arp": net_discovery.dscv_arp,
    "dscv_dhcp": net_discovery.dscv_dhcp,
    "dscv_tcp": net_discovery.dscv_tcp,
    "dscv_udp": net_discovery.dscv_udp
}

net_test_action_map: dict[str, Callable[[dict], object]] = {
    "spdtst" : net_test.start_iperf,
    "trcrt_dns" : net_test.traceroute_dns,
    "trcrt_syn" : net_test.traceroute_syn,
    "trcrt_udp" : net_test.traceroute_udp
}

wifi_action_map: dict[str, Callable[[dict], object]] = {
    "wifi_srvy_on": net_utils.start_survey,
    "wifi_srvy_off": net_utils.stop_survey,
    "wifi_srvy_rprt": net_utils.generate_report,   
    "wifi_srvy_json": net_utils.get_survey_json
}

async def _make_http_request(cmd: str, url: str, payload: dict = {}, headers: dict = {}, cookies: str = ''):
    async with httpx.AsyncClient() as client:
        match cmd:
            case 'p':
                client.cookies.set("access_token", value=cookies)
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
    async def enrollment(payload: dict = {}):
        headers = {'X-UMJ-WFLW-API-KEY': init_data.api_key}

        post_headers = {'X-UMJ-WFLW-API-KEY': init_data.api_key,
                        'Content-Type': 'application/json'}
        
        init_url=f"{init_data.url}/init?usr={init_data.usr}"

        enroll_url=f"{init_data.url}/enroll?usr={init_data.usr}&site={init_data.site}"

        resp_data = await _make_http_request(cmd='g', url=init_url, headers=headers)
        if resp_data.status_code == 200:
            access_token = resp_data.cookies.get('access_token')
            
            logger.info(access_token)
            enroll_rqst = await _make_http_request(cmd='p', url=enroll_url, headers=post_headers, cookies=access_token, payload=payload)
            if enroll_rqst.status_code == 200:
                return 200
            else:
                return 400
                 
    
    await prb_db.connect_db()
    prb_id, hstnm = probe_utils.gen_probe_register_data()

    if await prb_db.get_all_data(match=f'*{hstnm}*', cnfrm=True) is True:
        probe_data = await prb_db.get_all_data(match=f'*{hstnm}*')
        logger.info(probe_data)
        if init_data.enroll is False or init_data.api_key or init_data.usr or init_data.url or init_data.site is None or "".strip(): 
            return probe_data
        else:
           if await enrollment(payload=probe_data) != 200:
                return {"Error":"occurred during probe adoption"}, 400
           else:
                return probe_data
    else:
        probe_data=probe_utils.collect_local_stats(id=f"{id}", hostname=hstnm)
        probe_data['api_key'] = bcrypt.hash(str(uuid.uuid4()))
        logger.info(f"API Key for umjiniti probe {id}: {probe_data['api_key']}. Store this is a secure location as it will not be displayed again.")
        logger.info(probe_data)
    
        if await prb_db.upload_db_data(id=f"{prb_id}", data=probe_data) is not None:
             if init_data.enroll is False or init_data.api_key or init_data.usr or init_data.url or init_data.site is None or "".strip():
                return probe_data
             else:
                if await enrollment(payload=probe_data) != 200:
                    return {"Error":"occurred during probe adoption"}, 400
                else:
                    return probe_data

@api.post("/api/dscv")
def dscv(tool_data: ToolCall):
    handler = dscv_action_map.get(tool_data.action)
    if handler and tool_data.params is not None:
            ans, unans = handler(**tool_data.params)

@api.post("/api/test")
def test(tool_data: ToolCall):
    handler = net_test_action_map.get(tool_data.action)
    if handler and tool_data.params is not None:
            ans, unans = handler(**tool_data.params)

@api.post("/api/wifi")
def wifi(tool_data: ToolCall):
    handler = wifi_action_map.get(tool_data.action)
    if handler and tool_data.params is not None:
            ans, unans = handler(**tool_data.params)

@api.post("/api/prb")
def wifi(tool_data: ToolCall):
    handler = prb_action_map.get(tool_data.action)
    if handler and tool_data.params is not None:
            ans, unans = handler(**tool_data.params)

mcp = FastMCP.from_fastapi(app=api, name='umjiniti Network Util MCP')

mcp_app = mcp.http_app(path='/mcp')

api = FastAPI(title='umjiniti Network Util API', lifespan=mcp_app.lifespan, dependencies=[Depends(validate_api_key)])

api.mount("/llm", mcp_app)

# Run with: uvicorn app:api --host 0.0.0.0 --port 8000

# Install uvicorn with standard extras for better performance: pip install 'uvicorn[standard]'

# Run with multiple workers for better concurrency: uvicorn app:app --host 0.0.0.0 --port 8000 --workers 4

# Enable detailed logging for monitoring: uvicorn app:app --host 0.0.0.0 --port 8000 --log-level info