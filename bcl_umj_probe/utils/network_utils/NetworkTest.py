import os
import platform
import subprocess
import requests
import iperf3
from utils.network_utils.base.Network import Network
from scapy.all import *
from scapy import *
from scapy.tools import *
from scapy.layers.inet import *
from scapy.layers.l2 import *
from scapy.layers import dns
from scapy.layers.dns import *

class NetworkTest(Network):
    def __init__(self):
        super().__init__()

    def start_iperf(self, mode: str, remote_host: str, server_port=7969, duration=1, verbose=True, reverse=False, udp=False):
        match mode:
            case 'cl_tcp':
                if udp is False:
                    protocol='tcp'
                else:
                    protocol = 'udp'
                client = iperf3.Client()
                client.duration = duration
                client.server_hostname = remote_host
                client.protocol = protocol
                client.port = server_port
                client.blksize = 1234
                client.num_streams = 10
                client.zerocopy = True
                client.verbose = verbose
                client.reverse = reverse
                result = client.run()

                self.logger.info('')
                self.logger.info('Test completed:')
                self.logger.info('  started at         {0}'.format(result.time))
                self.logger.info('  bytes transmitted  {0}'.format(result.bytes))
                self.logger.info('  jitter (ms)        {0}'.format(result.jitter_ms))
                self.logger.info('  avg cpu load       {0}%\n'.format(result.local_cpu_total))

                self.logger.info('Average transmitted data in all sorts of networky formats:')
                self.logger.info('  bits per second      (bps)   {0}'.format(result.bps))
                self.logger.info('  Kilobits per second  (kbps)  {0}'.format(result.kbps))
                self.logger.info('  Megabits per second  (Mbps)  {0}'.format(result.Mbps))
                self.logger.info('  KiloBytes per second (kB/s)  {0}'.format(result.kB_s))
                self.logger.info('  MegaBytes per second (MB/s)  {0}'.format(result.MB_s))

                scan_result = {"test_start": result.time,
                               "bytes_trans": result.bytes,
                               "jitter": result.jitter_ms,
                               "avg_cpu_load": result.local_cpu_total,
                               "bps": result.bps,
                               "kbitps": result.kbps,
                               "mbitps": result.Mbps,
                               "kbytps": result.kB_s,
                               "mbytps": result.MB_s}

                return result.error if result.error else scan_result
              
            case 'sr':
                server = iperf3.Server()
                server.bind_address = '0.0.0.0'
                server.port = server_port
                server.verbose = True
                server.json_output=True
                server.run()

                """
                while True:
                   server.run()
                """
            case _:
                  return None

    def traceroute_syn(self, dest: str, port=80):
        """
        SYN traceroute

        Args:
            dest (str): host to trace route to

            port (int): service port to test (default HTTP)

        Returns:
            ans (SndRcvList): list of routers identified during trace
        """
        ans, unans = sr(IP(dst=dest,ttl=(1,10))/TCP(dport=port,flags="S", options=[('Timestamp',(0,0))]))
        ans.summary( lambda s,r: r.sprintf("%IP.src%\t{ICMP:%ICMP.type%}\t{TCP:%TCP.flags%}"))
        
        return ans if ans else None
    
    def traceroute_udp(self, target: str, app: None):
        """
        Traces UDP applications

        Args:
            dest (str): host to trace route to

            port (int): service port to test (default HTTP)

        Returns:
            router_list (str): list of routers identified during trace
        """

        res, unans = sr(IP(dst=target, ttl=(1,20)) /UDP()/app)

        router_list = res.make_table(lambda s,r: (s.dst, s.ttl, r.src))
        return router_list if not None else None
    
    def traceroute_dns(self, target: str, query: str):
        """
        Performs DNS traceroute

        Args:
            target (str): host to trace route to

            query (str): domain for query

        Returns:
            router_list (str): list of routers identified during trace
        """
        trc_result, packet_list = traceroute(target=target,l4=UDP(sport=RandShort())/DNS(qd=DNSQR(qname=query)))

        router_list = trc_result.make_lined_table(lambda s,r: (s.dst, r.src))
        return router_list if not None else None


       
