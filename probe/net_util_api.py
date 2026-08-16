from contextlib import asynccontextmanager
from fastapi import FastAPI, Depends, Response
from fastapi_user_limiter.limiter import rate_limiter
from pydantic import BaseModel
from init_app import (
    validate_api_key,
    init_probe, logger, prb_db, cron, check_for_utils,
    make_http_request, core_url, utility_scripts_path, get_probe_data, net_base
)
from net_util_mcp import mcp
from CoreClientv2 import CoreClient
import asyncio
from auto_scripts.script_base.base import run_task, schedule_cronjob
import json
import os
from datetime import datetime, timezone
from websockets import connect
import websockets
import uuid

class InitCall(BaseModel):
    umj_site: str
    umj_api_key: str
    prb_url: str
    prb_api_key: str
    prb_name: str

class ExecuteCall(BaseModel):
    tools_to_execute: list[dict] = None
    task_name: str = None
    schedule: dict = None
    user_id: str = None
    prb_id: str = None

class FlowCall(BaseModel):
    id: str
    probe: str
    flow: dict
    name: str
    user_id: str
    type: str
    schedule: dict = None

prb_id = None
hstnm = None
probe_data = None
websocket_url = None
mcp_app = mcp.http_app(path="/mcp")

async def send_over_websocket(data):
    if websocket_url is None:
        logger.warning("WebSocket URL is not set; cannot connect to umjini server. Skipping sending data over WebSocket.")
        return None
    async with connect(uri=websocket_url) as websocket:
        try:      
            await websocket.send(json.dumps(data))
        except websockets.exceptions.ConnectionClosed as e:
            logger.error(f"WebSocket connection closed: {e}")
        except websockets.exceptions.InvalidHandshake as ih:
            logger.error(f"WebSocket invalid handshake: {ih}")
        except websockets.exceptions.WebSocketException as we:
            logger.error(f"WebSocket exception: {we}")
        except asyncio.CancelledError:
            logger.info("connect_with_backoff cancelled")
        except Exception as e:
            logger.exception(f"Unexpected error connecting websocket: {e}")
        
@asynccontextmanager
async def combined_lifespan(app:FastAPI):
    async with mcp_app.lifespan(app):
        await prb_db.connect_db()
        await check_for_utils()
        global prb_id, hstnm, probe_data, websocket_url
        prb_id, hstnm, probe_data = await init_probe()
        websocket_url = f"wss://{os.getenv('CORE_URL')}/v1/api/core/channels/probe/heartbeat/{probe_data.get('prb_id')}"
        logger.info(f"Probe initialized: hostname={hstnm}")
        # idempotent guard
        if getattr(app.state, "core_client_started", False) is False and probe_data.get("umj_url"):
            app.state.core_client_started = True
            app.state.core_client = None
            app.state.core_client_task = None
            app.state.core_client_stop = None
            if websocket_url is None:
                logger.warning("WebSocket URL is not set; CoreClient will not be started")
                yield
                return
            core_client = CoreClient(umj_websocket_url=websocket_url)
            stop_event = asyncio.Event()
            app.state.core_client_stop = stop_event
            app.state.core_client = core_client
            app.state.core_client_task = asyncio.create_task(core_client.run(stop_event))
            logger.info("Started CoreClient task in FastAPI lifespan")
        
        yield
        
        stop_event = getattr(app.state, "core_client_stop", None)
        task = getattr(app.state, "core_client_task", None)

        if stop_event is not None:
            stop_event.set()

        if task is not None:
            try:
                await asyncio.wait_for(task, timeout=10.0)
            except asyncio.TimeoutError:
                logger.warning("CoreClient task did not exit in time; cancelling")
                task.cancel()
                try:
                    await task
                except Exception:
                    pass

            logger.info("CoreClient stopped and combined_lifespan exiting")

api = FastAPI(title='Network Util API', lifespan=combined_lifespan)

@api.get("/v1/api/status", dependencies=[Depends(rate_limiter(2, 5)), Depends(validate_api_key)])
def status():
    return Response(content='{"status": "ok"}', media_type="application/json", status_code=200)

@api.post("/v1/api/init", dependencies=[Depends(validate_api_key), Depends(rate_limiter(2, 5))])
async def init(init_data: InitCall):
    init_url = f"{core_url}/init?usr={os.getenv('ASSIGNED_USER')}"
    logger.info(init_url)
    enroll_url = f"{core_url}/enroll?usr={os.getenv('ASSIGNED_USER')}&site={init_data.umj_site}"
    logger.info(enroll_url)

    async def enrollment(payload: dict = {}):
        headers = {"X-UMJ-WFLW-API-KEY": init_data.umj_api_key}
        post_headers = {"X-UMJ-WFLW-API-KEY": init_data.umj_api_key,
                        "Content-Type": "application/json"}

        resp_data = await make_http_request(cmd="g", url=init_url, headers=headers)
        if resp_data.status_code == 200:
            access_token = resp_data.cookies.get("access_token")
            logger.info(access_token)
            enroll_rqst = await make_http_request(
                cmd="p",
                url=enroll_url,
                headers=post_headers,
                cookies=access_token,
                payload=payload,
            )
            return 200 if enroll_rqst.status_code == 200 else 400
        return None
    
    await prb_db.connect_db()

    probe_data['url'] = os.getenv('PROBE_URL')
    probe_data['umj_url'] = os.getenv('CORE_URL')
    probe_data['prb_api_key'] = init_data.prb_api_key
    probe_data['site'] = init_data.umj_site
    probe_data['name'] = init_data.prb_name
    probe_data['assigned_user'] = os.getenv('ASSIGNED_USER')
    logger.info(probe_data)

    if await enrollment(payload=probe_data) != 200:
        return Response(content='{"Error": "occurred during probe adoption"}', media_type="application/json", status_code=400)
    else:
        probe_info = await prb_db.get_all_data(match=f"prb-*")
        probe_info_dict = next(iter(probe_info.values()))
        probe_id = probe_info_dict.get('prb_id')
        probe_data['umj_api_key'] = init_data.umj_api_key
        probe_data.pop('prb_api_key')
        if await prb_db.upload_db_data(id=probe_id, data=probe_data) > 0:
            return Response(content='{"status": "ok"}', media_type="application/json", status_code=200)
        else:
            return Response(content='{"Error": "occurred during probe adoption"}', media_type="application/json", status_code=400)

@api.post("/v1/api/tasks/{command}", dependencies=[Depends(validate_api_key), Depends(rate_limiter(4, 10))])
async def tasks(command: str, tool_calls: ExecuteCall = None):
    match command:
        case 'exec':
            probe_info = await get_probe_data()
            parser_script_path = os.path.join(utility_scripts_path, f'Parsers.py')
            for tool in tool_calls.tools_to_execute:
                code, output, error, file_name = await run_task(action=tool.get('action'), params=json.dumps(tool.get('params')), snmp_community=tool.get('params').get('community') if 'community' in tool.get('params') else None)

                if code == 0:
                    parser_command = f"python3 {parser_script_path} --action {tool.get('action')} -o {output}"
                    
                    if str(tool.get('action')).startswith('scan'):
                        parser_command+=f' --file {file_name}'
                    
                    if str(tool.get('action')).startswith('trcrt'):
                        parser_command+=f' -tar {tool.get('params')["tool_prms"]["target"]} -pid {probe_info.get("prb_id")}'
                    
                    if str(tool.get('action')).startswith('pcap_'):
                        parser_command+=f' -i {tool.get('params')["tool_prms"]["interface"]}'
                    
                    parse_code, parse_output, parse_error = await net_base.run_shell_cmd(parser_command)
                else:
                    parsed_result = None

            return_data = {
                    "code": code,
                    "output": output,
                    "error": error,
                    "parsed_result": parsed_result

                }
            return Response(content=json.dumps(return_data), media_type="application/json", status_code=200 if code == 0 else 400)
        case 'init':      
            job1 = None
            cwd = os.getcwd() 
            now = datetime.now(tz=timezone.utc).isoformat()
            job_comment=f"auto_job_{probe_data.get('prb_id')}"
            task_command = ""
            script_path = os.path.join(cwd, 'auto_scripts', f'task_auto.py')
            task_command = f"python3 {script_path} -t '{json.dumps(tool_calls.tools_to_execute)}' -w {websocket_url} -pid '{probe_data.get('prb_id')}'"
            job_comment+=f"_{tool_calls.task_name}_{now}"
            job1 = await asyncio.to_thread(cron.new, command=task_command, comment=job_comment)
            scheduled_job = await asyncio.to_thread(schedule_cronjob, job1, tool_calls.schedule)

            if await asyncio.to_thread(scheduled_job.is_valid):
                await asyncio.to_thread(cron.write)
                await asyncio.sleep(1)
                logger.info(f"Cron job added: {scheduled_job}")
                return Response(content=json.dumps({
                        'site': probe_data.get('site'),
                        'prb_id': probe_data.get('prb_id'),
                        'prb_name': probe_data.get('name'),
                        'act': "task_cnfrm",
                        'comment': job_comment,
                        'enabled': 'enabled',
                        'storage_opt': 'new',
                        'user_id': tool_calls.user_id
                    }), media_type="application/json", status_code=200)
            else:
                logger.error("Invalid cron job, not writing to crontab.")
                return Response(content='invalid cron job', media_type="application/json", status_code=400)
        case 'disable':
            job = await asyncio.to_thread(cron.find_comment, comment=tool_calls.tools_to_execute[0]['comment'])
            await asyncio.to_thread(job.enable, False)
            await asyncio.to_thread(cron.write)
            await asyncio.sleep(1)
            tool_calls.tools_to_execute[0]['storage_opt'] = 'updt'
            tool_calls.tools_to_execute[0]['act'] = 'task_cnfrm'
            tool_calls.tools_to_execute[0]['task_output'] = f"Cron job '{tool_calls.tools_to_execute[0]['comment']}' disabled."
            await send_over_websocket(tool_calls.tools_to_execute[0])
            return Response(content=json.dumps(tool_calls.tools_to_execute[0]), media_type="application/json", status_code=200)
        case 'enable':
            job = await asyncio.to_thread(cron.find_comment, comment=tool_calls.tools_to_execute[0]['comment'])
            await asyncio.to_thread(job.enable, True)
            await asyncio.to_thread(cron.write)
            await asyncio.sleep(1)
            tool_calls.tools_to_execute[0]['storage_opt'] = 'updt'
            tool_calls.tools_to_execute[0]['act'] = 'task_cnfrm'
            tool_calls.tools_to_execute[0]['task_output'] = f"Cron job '{tool_calls.tools_to_execute[0]['comment']}' enabled."
            await send_over_websocket(tool_calls.tools_to_execute[0])
            return Response(content=json.dumps(tool_calls.tools_to_execute[0]), media_type="application/json", status_code=200)
        case 'remove':
            job = await asyncio.to_thread(cron.find_comment, comment=tool_calls.tools_to_execute[0]['comment'])
            await asyncio.to_thread(cron.remove, job)
            await asyncio.to_thread(cron.write)
            await asyncio.sleep(1)
            tool_calls.tools_to_execute[0]['act'] = 'task_cnfrm'
            tool_calls.tools_to_execute[0]['task_output'] = f"Cron job '{tool_calls.tools_to_execute[0]['comment']}' deleted."
            tool_calls.tools_to_execute[0]['storage_opt'] = 'del'
            await send_over_websocket(tool_calls.tools_to_execute[0])
            return Response(content=json.dumps(tool_calls.tools_to_execute[0]), media_type="application/json", status_code=200)
        case 'remove_all':
            await asyncio.to_thread(cron.remove_all)
            await asyncio.to_thread(cron.write)
            await asyncio.sleep(1)
            tool_calls.tools_to_execute[0]['act'] = 'task_cnfrm'
            tool_calls.tools_to_execute[0]['task_output'] = f"All cron jobs deleted."
            await send_over_websocket(tool_calls.tools_to_execute[0])
            return Response(content=json.dumps(tool_calls.tools_to_execute[0]), media_type="application/json", status_code=200)
        case 'reschedule':
            job = await asyncio.to_thread(cron.find_comment, comment=tool_calls.tools_to_execute[0]['comment'])
            if job:
                job = await asyncio.to_thread(schedule_cronjob, job, tool_calls.schedule)
                                    
            if await asyncio.to_thread(job.is_valid):
                await asyncio.to_thread(cron.write)
                await asyncio.sleep(1)
                logger.info(f"Cron job rescheduled: {job}")
                tool_calls.tools_to_execute[0]['enabled'] = 'enabled' if job.is_enabled() else 'disabled'
                tool_calls.tools_to_execute[0]['storage_opt'] = 'updt'
                tool_calls.tools_to_execute[0]['act'] = 'task_cnfrm'
                tool_calls.tools_to_execute[0]['task_output'] = f"Cron job '{tool_calls.tools_to_execute[0]['comment']}' rescheduled."
                await send_over_websocket(tool_calls.tools_to_execute[0])
                return Response(content=json.dumps(tool_calls.tools_to_execute[0]), media_type="application/json", status_code=200)
        case 'list':
            all_tasks = []
            for job in cron:
                if job.comment.startswith(f"auto_job_{probe_data.get('prb_id')}"):
                    task_info = {
                        "comment": job.comment,
                        "schedule": str(job.slices),
                        "command": job.command,
                        "enabled": job.is_enabled()
                    }
                    all_tasks.append(task_info)
            return Response(content=json.dumps(all_tasks), media_type="application/json", status_code=200) if all_tasks != [] else Response(content='{"status": "no tasks found"}', media_type="application/json", status_code=400)
        case _:
            pass

@api.get("/v1/api/flows/{command}", dependencies=[Depends(validate_api_key), Depends(rate_limiter(4, 10))])
async def flows(command: str, flow_data: FlowCall = None):
    match command:
        case 'list':
            all_flows = await prb_db.get_all_data(match=f"flow:*")
            all_flows_dict = next(iter(all_flows.values())) if all_flows is not None else None
            return Response(content=json.dumps(all_flows_dict), media_type="application/json", status_code=200) if all_flows_dict is not None else Response(content='{"status": "no flows found"}', media_type="application/json", status_code=400)     
        case 'delete':
            result = await prb_db.del_obj(key=flow_data.id)
            return Response(content='{"status": "flow deleted"}', media_type="application/json", status_code=200) if result is not None else Response(content='{"status": "flow deletion failed"}', media_type="application/json", status_code=400)
        case 'new':
            flow_data = {
                'id': flow_data.id,
                'prb_id': flow_data.probe,
                'flow': flow_data.flow,
                'name': flow_data.name,
                'user_id': flow_data.user_id
            }

            if flow_data.id == "default":
                flow_data.id = f"flow:{flow_data.name}:{str(uuid.uuid4())}"
                logger.info(flow_data.id)
              
            job1 = None
            cwd = os.getcwd() 
            now = datetime.now(tz=timezone.utc).isoformat()
            job_comment=f"auto_job_{probe_data.get('prb_id')}"
            task_command = ""
            script_path = os.path.join(cwd, 'auto_scripts', f'FlowRunner.py')
            task_command = f"python3 {script_path} -f '{json.dumps(flow_data.flow)}' -w {websocket_url} -pid '{probe_data.get('prb_id')}'"
            job_comment+=f"_{flow_data.name}_{now}"
            job1 = await asyncio.to_thread(cron.new, command=task_command, comment=job_comment)
            scheduled_job = await asyncio.to_thread(schedule_cronjob, job1, )

            if await asyncio.to_thread(scheduled_job.is_valid):
                await asyncio.to_thread(cron.write)
                await asyncio.sleep(1)
                logger.info(f"Cron job added: {scheduled_job}")
                result = await prb_db.upload_db_data(id=flow_data.id, data=flow_data)
                return Response(content=json.dumps({
                        'site': probe_data.get('site'),
                        'prb_id': probe_data.get('prb_id'),
                        'prb_name': probe_data.get('name'),
                        'act': "task_cnfrm",
                        'comment': job_comment,
                        'enabled': 'enabled',
                        'storage_opt': 'new',   
                        'user_id': flow_data.user_id
                    }), media_type="application/json", status_code=200)
            else:
                logger.error("Invalid cron job, not writing to crontab.")
                return Response(content='invalid cron job', media_type="application/json", status_code=400)
        case 'load':
            flow = await prb_db.get_all_data(match=f"*{flow_data.id}*")
            flow_data = next(iter(flow.values())) if flow is not None else None
            return Response(content=json.dumps(flow_data), media_type="application/json", status_code=200) if flow_data is not None else Response(content='{"status": "flow load failed"}', media_type="application/json", status_code=400)
        case 'edit':
            result = await prb_db.upload_db_data(id=flow_data.id, data={'flow': flow_data.flow})
            return Response(content='{"status": "flow edited"}', media_type="application/json", status_code=200) if result is not None else Response(content='{"status": "flow edit failed"}', media_type="application/json", status_code=400)
        case _:
            pass