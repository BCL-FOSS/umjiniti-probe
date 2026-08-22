from contextlib import asynccontextmanager
from fastapi import FastAPI, Depends, Response
from fastapi_user_limiter.limiter import rate_limiter
from pydantic import BaseModel
from init_app import (
    validate_api_key,
    init_probe, logger, prb_db, cron, check_for_utils,
    make_http_request, core_url, utility_scripts_path, get_probe_data, net_base, automation_scripts_path
)
from net_util_mcp import mcp
from CoreClientv2 import CoreClient
import asyncio
from auto_scripts.script_base.base import run_task, schedule_cronjob
import json
import os
from datetime import datetime, timezone
import uuid

class InitCall(BaseModel):
    umj_api_key: str
    prb_api_key: str

class ExecuteCall(BaseModel):
    tools_list: str
    flow_name: str

class FlowCall(BaseModel):
    comment: str = None
    flow: str = None
    name: str = None
    user_id: str = None
    schedule: str = None

mcp_app = mcp.http_app(path="/mcp")
        
@asynccontextmanager
async def combined_lifespan(app:FastAPI):
    async with mcp_app.lifespan(app):
        await prb_db.connect_db()
        await check_for_utils()
        websocket_url = None
        prb_id, hstnm, probe_data = await init_probe()
        if probe_data['enrolled'] == 'y':
            websocket_url = f"wss://{core_url}/channels/{prb_id}/{0}"
            logger.info(f"Probe initialized: hostname={hstnm}")
        # idempotent guard
        if getattr(app.state, "core_client_started", False) is False:
            app.state.core_client_started = True
            app.state.core_client = None
            app.state.core_client_task = None
            app.state.core_client_stop = None
            if websocket_url is None:
                logger.warning("WebSocket URL is not set; CoreClient will not be started")
                yield
                return
            core_client = CoreClient(umj_websocket_url=websocket_url, connect_ws=probe_data.get('enrolled'))
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

@api.post("/v1/api/init", dependencies=[Depends(validate_api_key), Depends(rate_limiter(2, 5))])
async def init(init_data: InitCall):
    init_url = f"{core_url}/init?usr={os.getenv('PROBE_USER')}"
    logger.info(init_url)
    enroll_url = f"{core_url}/enroll?usr={os.getenv('PROBE_USER')}&site={os.getenv('PROBE_SITE')}"
    logger.info(enroll_url)

    async def enrollment(payload: dict = {}):
        headers = {"X-UMJ-WFLW-API-KEY": init_data.umj_api_key}
        post_headers = headers.copy()
        post_headers['Content-Type'] = "application/json"

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
    
    probe_data = await get_probe_data()
    probe_data['prb_api_key'] = init_data.prb_api_key
    probe_data['available_tools'] = json.dumps(mcp.get_tools())
    logger.info(probe_data)

    if await enrollment(payload=probe_data) != 200:
        return Response(status_code=400)
    else:
        await prb_db.connect_db()
        probe_data.pop('prb_api_key')
        if await prb_db.upload_db_data(id=probe_data.get('prb_id'), data=probe_data) > 0:
            return Response(status_code=200)
        else:
            return Response(status_code=400)

@api.post("/v1/api/tasks/exec", dependencies=[Depends(validate_api_key), Depends(rate_limiter(4, 10))])
async def exec(tool_calls: ExecuteCall = None):
    probe_info=await get_probe_data()
    parser_script_path=os.path.join(utility_scripts_path, f'Parsers.py')
    selected_tools = json.loads(tool_calls.tools_list)
    documents=[]
    
    main_content=f"network Tool(s) Output for Probe: {probe_info.get('prb_id')}\n\n"
    for tool in selected_tools:
        now = datetime.now(tz=timezone.utc).isoformat()
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

            content = f"Tool: {tool.get('action')}\n"
            content += f"Timestamp: {now}\n"
            content += f"Raw Output:\n{output}\n"
            content += f"Parsed Output:\n{parse_output}\n\n"
            doc_id = f"{tool_calls.flow_name}_{now}_{probe_info.get('prb_id')}_{str(uuid.uuid4())}"

            if parse_code == 0:
                documents.append({
                    "tool_type": f"{tool.get('action')}",
                    "output": f"{output}",
                    "content": content,
                    "metadata": {
                        "prb_id": f"{probe_info.get('prb_id')}",
                        "timestamp": f"{now}",
                        "tool_type": f"{tool.get('action')}",
                        "type": f"flow_{tool_calls.flow_name}"
                                },
                    "auto_execute": False,
                    "id": doc_id
                })
                main_content+=f"{content}\n"
            else:
                pass
           
    return Response(content={'output': json.dumps(documents), 'anlys_output': main_content}, media_type="application/json", status_code=200)

@api.get("/v1/api/flows/{command}", dependencies=[Depends(validate_api_key), Depends(rate_limiter(4, 10))])
async def flows(command: str, flow_calls: FlowCall = None):
    probe_data = await get_probe_data()
    match command:
        case 'new':
            flow_payload = {
                'prb_id': probe_data.get('prb_id'),
                'flow': flow_calls.flow,
                'user_id': flow_calls.user_id,
                'schedule': flow_calls.schedule
            }
            job1 = None 
            now = datetime.now(tz=timezone.utc).isoformat()
            job_comment=f"auto_job:{probe_data.get('prb_id')}:{flow_calls.name}:{now}:{str(uuid.uuid4())}"
            task_command = ""
            script_path = os.path.join(automation_scripts_path, f'FlowRunner.py')
            task_command = f"python3 {script_path} -f '{flow_calls.flow}' -n '{job_comment}'"
            job1 = await asyncio.to_thread(cron.new, command=task_command, comment=job_comment)
            scheduled_job = await asyncio.to_thread(schedule_cronjob, job1, json.loads(flow_calls.schedule))
            if await asyncio.to_thread(scheduled_job.is_valid):
                await asyncio.to_thread(cron.write)
                flow_payload['comment'] = job_comment
                if await prb_db.upload_db_data(id=flow_payload['comment'], data=flow_payload) > 0:
                    return Response(content=json.dumps({'comment': flow_payload['comment']}), media_type="application/json", status_code=200)
            else:
                return Response(status_code=400)
        case 'disable':
            job = await asyncio.to_thread(cron.find_comment, comment=flow_calls.comment)
            await asyncio.to_thread(job.enable, False)
            await asyncio.to_thread(cron.write)
            if await prb_db.upload_db_data(id=flow_calls.comment, data={'enabled': 'disabled'}) > 0:
                return Response(status_code=200)
        case 'enable':
            job = await asyncio.to_thread(cron.find_comment, comment=flow_calls.comment)
            await asyncio.to_thread(job.enable, True)
            await asyncio.to_thread(cron.write)
            if await prb_db.upload_db_data(id=flow_calls.comment, data={'enabled': 'enabled'}) > 0:
                return Response(status_code=200)
        case 'remove':
            job = await asyncio.to_thread(cron.find_comment, comment=flow_calls.comment)
            await asyncio.to_thread(cron.remove, job)
            await asyncio.to_thread(cron.write)   
            if await prb_db.del_obj(key=flow_calls.comment) is not None:        
                return Response(status_code=200)
        case 'remove_all':
            await asyncio.to_thread(cron.remove_all)
            await asyncio.to_thread(cron.write)
            return Response(status_code=200)
        case 'reschedule':
            job = await asyncio.to_thread(cron.find_comment, comment=flow_calls.comment)
            if job:
                job = await asyncio.to_thread(schedule_cronjob, job, flow_calls.schedule)                      
            if await asyncio.to_thread(job.is_valid):
                await asyncio.to_thread(cron.write)            
                return Response(status_code=200)
        case 'load':
            flow = await prb_db.get_all_data(match=f"{flow_calls.comment}")
            selected_flow_data = next(iter(flow.values())) if flow is not None else None
            return Response(content=json.dumps(selected_flow_data), media_type="application/json", status_code=200)
        case 'list':
                    all_flows = await prb_db.get_all_data(match=f"auto_job:*")
                    all_flows_dict = next(iter(all_flows.values())) if all_flows is not None else None
                    return Response(content=json.dumps(all_flows_dict), media_type="application/json", status_code=200) if all_flows_dict is not None else Response(status_code=400)  
        case 'edit':
            result = await prb_db.upload_db_data(id=flow_calls.comment, data={'flow': flow_calls.flow})
            return Response(status_code=200) if result is not None else Response(status_code=400)
        case _:
            pass