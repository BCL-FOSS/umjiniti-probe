import datetime
import ast
from datetime import datetime, timezone
from probe.init_app import log_alert, logger, get_probe_data, make_http_request, utility_scripts_path, net_base, core_url
from probe.net_util_api import core_url
from script_base.base import run_task
import json
import argparse
import asyncio
import os

class FlowRunner:
    def __init__(self):
        self.logger = logger

    async def run(self, flow_str: str):
        probe_data_dict = await get_probe_data()
        self.logger.info(f"Probe Data From FlowRunner: {probe_data_dict}")
        flow_dict = ast.literal_eval(flow_str)
        # Parsed flow data
        workflow = flow_dict
        self.logger.info(workflow)
        workflow_data = workflow['drawflow']['Home']['data']
        self.logger.info(workflow_data)
        alerts = []
        agents = [{}]
        local_tools_to_execute = {}
        for node_id, node in workflow_data.items():
            node_data = node.get('data')
            match node_data['name']:
                case 'scans':
                    params = {}
                    if node_data['scan-type']:
                        local_tools_to_execute[node_id]['tool'] = node_data['scan-type']

                    if node_data['scan-target']:
                        params['tool_prms']['target'] = node_data['scan-target']

                    if node_data['scan-useiface'] == 'n' and node_data['scan-iface']:
                        params['interface'] = node_data['scan-iface']

                    if node_data['scan-snmpscripts'] and node_data['scan-type'] == 'scan_snmp':
                        params['tool_prms']['scripts'] = node_data['scan-snmpscripts']

                    if node_data['scan-snmpcommunity'] and node_data['scan-type'] == 'scan_snmp':
                        params['community'] = node_data['scan-snmpcommunity']

                    if node_data['scan-options']:
                        params['tool_prms']['options'] = node_data['scan-options']

                    if node_data['scan-vulnscore'] and node_data['scan-type'] == 'scan_vuln':
                        params['tool_prms']['min_score'] = node_data['scan-vulnscore']

                    if node_data['scan-map-syn'] and node_data['scan-type'] == 'scan_map':
                        params['tool_prms']['syn_ports'] = node_data['scan-map-syn']

                    if node_data['scan-map-ack'] and node_data['scan-type'] == 'scan_map':
                        params['tool_prms']['ack_ports'] = node_data['scan-map-ack']

                    local_tools_to_execute[node_id]['prms'] = params

                case 'pcaps':
                    params = {}
                    if node_data['pcap-mode']:
                        local_tools_to_execute[node_id]['tool'] = node_data['pcap-mode']

                    if node_data['pcap-useiface'] == 'n' and node_data['pcap-iface'] and node_data['pcap-mode'] == 'pcap_lcl':
                        params['interface'] = node_data['pcap-iface']

                    if (node_data['pcap-rmhost'] and node_data['pcap-rmuser'] and node_data['pcap-rmpass'] and node_data['pcap-rmiface']) and node_data['pcap-mode'] != 'pcap_lcl':
                        params['tool_prms']['host'] = node_data['pcap-rmhost']
                        params['tool_prms']['usr'] = node_data['pcap-rmuser']
                        params['tool_prms']['pwd'] = node_data['pcap-rmpass']
                        params['tool_prms']['remote_interface'] = node_data['pcap-rmiface']

                    if node_data['pcap-duration'] and node_data['pcap-mode'] == 'pcap_win':
                        params['tool_prms']['duration'] = node_data['pcap-duration']

                    if node_data['pcap-count'] and (node_data['pcap-mode'] == 'pcap_lcl' or node_data['pcap-mode'] == 'pcap_tux'):
                        params['tool_prms']['cap_count'] = node_data['pcap-count']

                    local_tools_to_execute[node_id]['prms'] = params

                case 'test_srvr':
                    params = {}
                    if node_data['perfs-options']:
                        params['tool_prms']['options'] = node_data['perfs-options']

                    if node_data['perfs-bind']:
                        params['tool_prms']['host'] = node_data['perfs-bind']

                    local_tools_to_execute[node_id] = {'tool': node_data['name'], 'prms': params}

                case 'test_clnt':
                    params = {}
                    if node_data['perfc-options']:
                        params['tool_prms']['options'] = node_data['perfc-options']

                    if node_data['perfc-server']:
                        params['tool_prms']['server'] = node_data['perfc-server']

                    if node_data['perfc-bind']:
                        params['tool_prms']['host'] = node_data['perfc-bind']

                    local_tools_to_execute[node_id] = {'tool': node_data['name'], 'prms': params}

                case 'trcrt':
                    params = {}
                    if node_data['trcrt-options']:
                        params['tool_prms']['options'] = node_data['trcrt-options']

                    if node_data['trcrt-target']:
                        params['tool_prms']['target'] = node_data['trcrt-target']

                    if node_data['trcrt-pktlen']:
                        params['tool_prms']['packetlen'] = node_data['trcrt-pktlen']

                    local_tools_to_execute[node_id] = {'tool': node_data['name'], 'prms': params}

                case 'trcrt_dns':
                    params = {}
                    if node_data['trcrtdns-options']:
                        params['tool_prms']['options'] = node_data['trcrtdns-options']

                    if node_data['trcrtdns-target']:
                        params['tool_prms']['target'] = node_data['trcrtdns-target']

                    if node_data['tracrtdns-server']:
                        params['tool_prms']['server'] = node_data['tracrtdns-server']

                    local_tools_to_execute[node_id] = {'tool': node_data['name'], 'prms': params}

                case 'slack' | 'jira' | 'email':
                    alerts.append(node_data['name'])

                case 'smartbot':
                    if node_data['bot-prompt']:
                        agents[0]['prompt'] = node_data['bot-prompt']
                        agents[0]['agent'] = node_data['name']

        if local_tools_to_execute != {}:
            parser_script_path = os.path.join(utility_scripts_path, f'Parsers.py')
            task_output=""
            for node_id, tool_info in local_tools_to_execute.items():
                code, output, error, file_name = await run_task(action=tool_info['tool'], params=json.dumps(tool_info['prms']), snmp_community=tool_info['prms'].get('community') if 'community' in tool_info['prms'] else None)

                parser_command = f"python3 {parser_script_path} --action {tool_info['tool']} -o {output}"

                if str(tool_info['tool']).startswith('scan'):
                    parser_command+=f' --file {file_name}'

                if str(tool_info['tool']).startswith('trcrt'):
                    parser_command+=f' -tar {tool_info["prms"]["tool_prms"]["target"]} -pid {probe_data_dict.get("prb_id")}'

                if str(tool_info['tool']).startswith('pcap_'):
                    parser_command+=f' -i {tool_info["prms"]["tool_prms"]["interface"]}'

                parse_code, parse_output, parse_error = await net_base.run_shell_cmd(parser_command)

                if parse_code == 0:
                    task_output+=f"Task:{tool_info['tool']}\nProbe:{probe_data_dict.get('prb_id')}\nOutput: {parse_output}\n\n"
                else:
                    task_output+=f"Task:{tool_info['tool']}\nProbe:{probe_data_dict.get('prb_id')}\nStatus: {parse_error}\n\n"

            headers = {"X-UMJ-WFLW-API-KEY": os.getenv('UMJ_WFLW_API_KEY')}
            post_headers = headers.copy()
            post_headers["Content-Type"] = "application/json"
            resp_data = await make_http_request(cmd='g', url=f"{core_url}/init?usr={os.getenv('ASSIGNED_USER')}", headers=headers)
            if resp_data.status_code == 200:
                access_token = resp_data.cookies.get("access_token")
                logger.info(access_token)
                analysis_prompt = (
                    f"{task_output}"
                    + "\n\n"
                    + f"{agents[0]['prompt']}"
                )
                notif_list = ','.join(alerts)
                resp_analysis = await make_http_request(cmd='p', url=f"{core_url}/analysis", headers=post_headers, payload=json.dumps({"prompt": analysis_prompt, "name": agents[0]['agent'], "notif_list": notif_list, "prb_id": probe_data_dict.get('prb_id'), "task_output": task_output}), cookies=access_token)

                if resp_analysis.status_code == 200:
                    timestamp = datetime.now(tz=timezone.utc).isoformat()
                    await log_alert.write_log(log_name=f"{tool_info['tool']}_result_{timestamp}", message=task_output)
                    return
    
if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Run local network automation workflows.")
    parser.add_argument(
        '-f', '--flow', 
        type=str, 
        help="Network flow to execute"
    )
    parser.add_argument(
        '-n', '--name', 
        type=str, 
        help="Name of the workflow"
    )
    args = parser.parse_args()
    workflow_runner = FlowRunner()
    asyncio.run(workflow_runner.run(flow_str=str(args.flow)))