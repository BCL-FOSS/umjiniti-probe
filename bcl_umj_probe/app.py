from init_app import (api, logger, validate_api_key, prb_db, probe_utils, net_utils, net_test, net_discovery, net_snmp, probe_data, prb_id)
from typing import Callable
import httpx
from fastmcp import FastMCP
from fastapi import FastAPI, Depends
from pydantic import BaseModel
import inspect

class Init(BaseModel):
    api_key: str 
    usr: str 
    url: str 
    site: str 
    enroll: bool

class ToolCall(BaseModel):
    action: str 
    params: dict 

prb_action_map: dict[str, Callable[[dict], object]] = {
    "prbdta": probe_utils.get_probe_data,
    "prbprc": probe_utils.get_processes_by_names,
    "prbprt": probe_utils.open_listening_ports,
    "prbifc": probe_utils.get_iface_ips
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

snmp_action_map: dict[str, Callable[[dict], object]] = {
   
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
    ping = await prb_db.ping_db()
    logger.info(f'redis db ping result: {ping}')

    if await prb_db.upload_db_data(id=f"{prb_id}", data=probe_data) is not None:
        if init_data.enroll is False or init_data.api_key or init_data.usr or init_data.url or init_data.site is None or "".strip(): 
            return probe_data
        
        logger.info(f'probe data for {prb_id} generated successfully')
        if await enrollment(payload=probe_data) != 200:
            return {"Error":"occurred during probe adoption"}, 400
        else:
            return 200

@api.post("/api/dscv")
async def dscv(tool_data: ToolCall):
    """
    Use for network device mapping/discovery, target host identification and dhcp server identification.
    """
    handler = dscv_action_map.get(tool_data.action)
    if handler and tool_data.params is not None:
        if inspect.iscoroutinefunction(handler):
            data = await handler(**tool_data.params)
        else:
            data = handler(**tool_data.params)
        return data

@api.post("/api/test")
def test(tool_data: ToolCall):
    """
    Use to perform network speedtest between two probes using the probe as either a server or client (uses iperf to perform the speedtest) and traceroutes such as SYN, UDP (to trace UDP applications) and DNS.
    """
    handler = net_test_action_map.get(tool_data.action)
    if handler and tool_data.params is not None:
        data = handler(**tool_data.params)
        return data

@api.post("/api/wifi")
def wifi(tool_data: ToolCall):
    handler = wifi_action_map.get(tool_data.action)
    if handler and tool_data.params is not None:
            ans, unans = handler(**tool_data.params)

@api.post("/api/prb")
def wifi(tool_data: ToolCall):
    """
    Use for host system data such as local stats, running processes, open listening ports and interfaces with assosciated IP addresses.
    """
    handler = prb_action_map.get(tool_data.action)
    if handler and tool_data.params is not None:
        data = handler(**tool_data.params)
        return data

mcp = FastMCP.from_fastapi(app=api, name='umjiniti Network Util MCP')

mcp_app = mcp.http_app(path='/mcp')

api = FastAPI(title='umjiniti Network Util API', lifespan=mcp_app.lifespan, dependencies=[Depends(validate_api_key)])

api.mount("/llm", mcp_app)

# Run with: uvicorn app:api --host 0.0.0.0 --port 8000

# Install uvicorn with standard extras for better performance: pip install 'uvicorn[standard]'

# Run with multiple workers for better concurrency: uvicorn app:app --host 0.0.0.0 --port 8000 --workers 4

# Enable detailed logging for monitoring: uvicorn app:app --host 0.0.0.0 --port 8000 --log-level info