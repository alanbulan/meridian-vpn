#!/usr/bin/env python3
# Modified version for Meridian; publication notices added 2026-11-03.
# This file differs from pinned upstream OpenConnect through the documented
# UniVPN and Meridian patch series. Original authorship and license notices
# remain unchanged. Earlier patch dates are preserved where recorded; this
# date identifies the notice addition, not an invented original change date.
"""Both real TLS channels + native lifecycle pipe; no interface or privileged call."""
import importlib.util, json, os, pathlib, socket, subprocess, sys
spec=importlib.util.spec_from_file_location('mock',pathlib.Path(__file__).with_name('univpn-integration.py'))
mock=importlib.util.module_from_spec(spec);spec.loader.exec_module(mock)
mock.Integration.setUpClass()
gateway=mock.Gateway(mock.Integration.ctx,auth_delay=.2)
rd,wr=os.pipe();sockets=[]
try:
    sockets=[socket.create_connection(('127.0.0.1',gateway.port)) for _ in range(2)]
    cmd=[str(pathlib.Path(__file__).with_name('univpn-fd-session')),str(mock.Integration.cert),
         'https://broker-only.invalid:'+str(gateway.port),str(wr),*(str(s.fileno()) for s in sockets)]
    result=subprocess.run(cmd,capture_output=True,pass_fds=(wr,*(s.fileno() for s in sockets)),
                          env={**os.environ,'LD_PRELOAD':str(mock.Integration.shim)},timeout=15)
    os.close(wr);wr=-1
    wire=os.read(rd,32768)
    assert os.read(rd,1)==b''
    assert result.returncode==0,result.stderr
    assert json.loads(wire)=={'version':1,'event':'no-network','session':'0123456789abcdef0123456789abcdef'},wire
    assert gateway.count==2 and gateway.errors==[],gateway.errors
    print(result.stdout.decode().strip())
finally:
    os.close(rd)
    if wr>=0:os.close(wr)
    for sock in sockets:sock.close()
    gateway.close();mock.Integration.tearDownClass()
