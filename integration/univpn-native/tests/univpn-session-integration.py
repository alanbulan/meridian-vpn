#!/usr/bin/env python3
# Modified version for Meridian; publication notices added 2026-11-03.
# This file differs from pinned upstream OpenConnect through the documented
# UniVPN and Meridian patch series. Original authorship and license notices
# remain unchanged. Earlier patch dates are preserved where recorded; this
# date identifies the notice addition, not an invented original change date.
"""Native pipe CLI with real loopback TLS authentication, never TUN setup."""
import importlib.util
import json
import os
import pathlib
import subprocess
import socket
import sys
spec = importlib.util.spec_from_file_location('mock', pathlib.Path(__file__).with_name('univpn-integration.py'))
mock = importlib.util.module_from_spec(spec)
spec.loader.exec_module(mock)  # consumes binary argument
mock.Integration.setUpClass()
nonce = '0123456789abcdef0123456789abcdef'
try:
    for auth_ok, preconnected in ((False,False),(True,False),(False,True),(True,True)):
        gateway = mock.Gateway(mock.Integration.ctx, auth_ok=auth_ok)
        rd, wr = os.pipe()
        try:
            cmd = [mock.BINARY, '--no-proxy', '--protocol=univpn', '--non-inter',
                   '--user=mockuser', '--passwd-on-stdin', '--authgroup=localhost',
                   '--no-dtls', '--authenticate', '--cafile='+str(mock.Integration.cert),
                   '--meridian-session-fd='+str(wr), '--meridian-session-id='+nonce,
                   'https://127.0.0.1:'+str(gateway.port)]
            sockets = []
            if preconnected:
                sockets = [socket.create_connection(('127.0.0.1',gateway.port)) for _ in range(2)]
                cmd += ['--meridian-control-fd='+str(sockets[0].fileno()), '--meridian-data-fd='+str(sockets[1].fileno())]
            try:
                result = subprocess.run(cmd, input=b'mock&+%pass\n', capture_output=True,
                                        pass_fds=(wr,)+tuple(s.fileno() for s in sockets), timeout=15,
                                        env={**os.environ, **({'LD_PRELOAD':str(mock.Integration.shim)} if preconnected else {})})
            finally:
                for sock in sockets: sock.close()
            os.close(wr); wr = -1
            wire = os.read(rd, 32768)
            assert os.read(rd, 1) == b''
            assert json.loads(wire) == {'version': 1, 'event': 'no-network', 'session': nonce}, wire
            assert result.returncode == (0 if auth_ok else 1), result.stderr
            assert b'mock&+%pass' not in wire and b'config' not in wire
        finally:
            os.close(rd)
            if wr >= 0: os.close(wr)
            gateway.close()
    print('Native pipe CLI authentication success/rejection passed (loopback TLS, authenticate-only, no TUN)')
finally:
    mock.Integration.tearDownClass()
