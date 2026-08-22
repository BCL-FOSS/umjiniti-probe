import asyncio
import websockets
from websockets.sync.client import ClientConnection
from websockets.sync.client import connect
import json
from typing import Optional
import asyncio
from probe.init_app import logger, get_probe_data, probe_util

class CoreClient:
    def __init__(self, umj_ws_url: str | None, connect_ws: str = 'n'):
        self.logger = logger
        self.umj_ws = umj_ws_url
        self.connect_ws = connect_ws
        
    def stop(self):
            if getattr(self, "_stop_event", None) is not None:
                try:
                    self._stop_event.set()
                except Exception:
                    pass
            self._internal_stop = True

    async def connect_with_backoff(self, ws_url: str | None, stop_event: Optional[asyncio.Event] = None):
        probe_data_dict = await get_probe_data()

        if stop_event is None:
            stop_event = asyncio.Event()
        self._stop_event = stop_event
        self._internal_stop = False

        self.logger.info("CoreClient: entering connect_with_backoff loop")

        if self.connect_ws == 'y':
            async with connect(uri=ws_url) as websocket:
                self.logger.info(f"Connected to {ws_url}")

                while not stop_event.is_set() and not getattr(self, "_internal_stop", False):
                    try:
                        if stop_event.is_set() or getattr(self, "_internal_stop", False):
                            self.logger.info("Stop requested, exiting connect loop after clean disconnect")
                            break

                        await self.interact(websocket, probe_obj=probe_data_dict, stop_event=stop_event)
                
                        await asyncio.wait_for(stop_event.wait(), timeout=0.5)

                    except websockets.exceptions.ConnectionClosed as e:
                        self.logger.error(f"WebSocket connection closed: {e}")
                    except websockets.exceptions.InvalidHandshake as ih:
                        self.logger.error(f"WebSocket invalid handshake: {ih}")
                    except websockets.exceptions.WebSocketException as we:
                        self.logger.error(f"WebSocket exception: {we}")
                    except asyncio.CancelledError:
                        self.logger.info("connect_with_backoff cancelled")
                    except Exception as e:
                        self.logger.exception(f"Unexpected error connecting websocket: {e}")

        self.logger.info("CoreClient: exiting connect_with_backoff")

    async def interact(self, ws: ClientConnection, probe_obj: dict, stop_event: Optional[asyncio.Event] = None):
        if stop_event is None:
            stop_event = asyncio.Event()

        async def _heartbeat():
            while not stop_event.is_set() and not getattr(self, "_internal_stop", False):
                ping = {
                    "sess_id": probe_obj.get('prb_id'),
                    "act": "hb"
                }
                try:
                    await ws.send(json.dumps(ping))
                except websockets.ConnectionClosed:
                    self.logger.warning("Heartbeat: connection closed")
                    break
                except asyncio.CancelledError:
                    break
                except Exception:
                    self.logger.exception("Heartbeat: failed to send ping")
                    break
                try:
                    await asyncio.wait_for(stop_event.wait(), timeout=30.0)
                    break
                except asyncio.TimeoutError:
                    continue

        async def _probe_stats_update():
            while not stop_event.is_set() and not getattr(self, "_internal_stop", False):
                stats = asyncio.to_thread(probe_util.collect_local_stats)
                payload = {
                    "sess_id": probe_obj.get('prb_id'),
                    "act": "updt",
                    "stats": json.dumps(stats)
                }
                try:
                    await ws.send(json.dumps(payload))
                except websockets.ConnectionClosed:
                    self.logger.warning("Stat collect: connection closed")
                    break
                except asyncio.CancelledError:
                    break
                except Exception:
                    self.logger.exception("Stat collect: failed to send ping")
                    break
                try:
                    await asyncio.wait_for(stop_event.wait(), timeout=600.0)
                    break
                except asyncio.TimeoutError:
                    continue
       
        hb_task = asyncio.create_task(_heartbeat())
        updt_task = asyncio.create_task(_probe_stats_update())
        done, pending = await asyncio.wait([hb_task, updt_task], return_when=asyncio.FIRST_COMPLETED)

        for t in pending:
            t.cancel()
            try:
                await t
            except Exception:
                pass
        self.logger.debug("Interact finished (heartbeat)")

    async def run(self, stop_event: Optional[asyncio.Event] = None):
        self.logger.info("CoreClient.run starting")
        if stop_event is None:
            stop_event = asyncio.Event()
        self._stop_event = stop_event
        self._internal_stop = False

        try:
            await self.connect_with_backoff(ws_url=self.umj_ws, stop_event=stop_event)
        except asyncio.CancelledError:
            self.logger.info("CoreClient.run cancelled")
            raise
        except Exception:
            self.logger.exception("Unhandled exception in CoreClient.run")
        finally:
            self.logger.info("CoreClient.run finished")