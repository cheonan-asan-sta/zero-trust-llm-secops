"""Bounded loopback-only HTTP transport for local collector integration tests."""

import socket
import threading
import time
from contextlib import contextmanager

import uvicorn

from app.config import get_settings
from scripts.f1_lab.web_evidence_ledger import require


@contextmanager
def loopback_http(app):
    require(get_settings().app_environment in {'local','test'},'web_capture_transport_local_only')
    listener = socket.socket(socket.AF_INET,socket.SOCK_STREAM)
    listener.bind(('127.0.0.1',0))
    port = listener.getsockname()[1]
    server = uvicorn.Server(uvicorn.Config(app,host='127.0.0.1',port=port,access_log=False,log_level='critical',
        proxy_headers=False,lifespan='off',ws='none',timeout_keep_alive=1))
    worker = threading.Thread(target=server.run,kwargs={'sockets':[listener]},daemon=True)
    worker.start()
    try:
        deadline = time.monotonic()+5
        while not server.started and worker.is_alive() and time.monotonic() < deadline:
            time.sleep(.01)
        require(server.started and worker.is_alive(),'web_capture_transport_start')
        yield f'http://127.0.0.1:{port}'
    finally:
        server.should_exit = True
        worker.join(10)
        if worker.is_alive():
            server.force_exit = True
            worker.join(2)
        listener.close()
        require(not worker.is_alive(),'web_capture_transport_stop')
