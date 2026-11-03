#!/usr/bin/env python3
# Modified version for Meridian; publication notices added 2026-11-03.
# This file differs from pinned upstream OpenConnect through the documented
# UniVPN and Meridian patch series. Original authorship and license notices
# remain unchanged. Earlier patch dates are preserved where recorded; this
# date identifies the notice addition, not an invented original change date.
"""Exercise the real native client against a loopback-only mock TLS gateway.
No root/TUN device, remote server or private configuration is needed.
Run: python3 tests/univpn-integration.py [path-to-openconnect]
"""
import os
import pathlib
import shlex
import signal
import socket
import ssl
import struct
import subprocess
import sys
import tempfile
import threading
import time
import unittest

BINARY = str(pathlib.Path(sys.argv.pop(1) if len(sys.argv) > 1 else './openconnect').resolve())
MAGIC = bytes.fromhex('c192a4d601')
TOKEN = bytes(range(32))
assert len(TOKEN) == 32

def exact(sock, size):
    result = b''
    while len(result) < size:
        part = sock.recv(size - len(result))
        if not part:
            raise EOFError()
        result += part
    return result

def frame(cmd, body=b''):
    return MAGIC + struct.pack('!BH', cmd, len(body)) + body

def receive(sock):
    header = exact(sock, 8)
    if header[:5] != MAGIC:
        raise ValueError('bad header')
    return header[5], exact(sock, struct.unpack('!H', header[6:])[0])

def tlv(kind, value):
    return struct.pack('!HH', kind, len(value)) + value

class Gateway:
    def __init__(self, ctx, auth_ok=True, malformed=False, data_ctx=None, stalled=None, auth_delay=0):
        self.ctx, self.auth_ok, self.malformed = ctx, auth_ok, malformed
        self.stalled = stalled
        self.auth_delay = auth_delay
        self.data_ctx, self.count = data_ctx, 0
        self.closed = 0
        self.closed_lock = threading.Lock()
        self.listener = socket.socket()
        self.listener.bind(('127.0.0.1', 0))
        self.port = self.listener.getsockname()[1]
        self.listener.listen()
        self.listener.settimeout(.2)
        self.stop = threading.Event()
        self.sockets, self.errors, self.received = [], [], []
        self.thread = threading.Thread(target=self.accept, daemon=True)
        self.thread.start()
    def accept(self):
        while not self.stop.is_set():
            try:
                raw, _ = self.listener.accept()
            except socket.timeout:
                continue
            except OSError:
                return
            self.sockets.append(raw)
            ctx = self.data_ctx if self.count and self.data_ctx else self.ctx
            self.count += 1
            threading.Thread(target=self.handle, args=(raw,ctx), daemon=True).start()
    def send(self, sock, cmd, body):
        # Header/body fragmentation also exercises handshake buffering.
        data = frame(cmd, body)
        if cmd == 0x66:
            sock.sendall(data)
            return
        for part in (data[:3], data[3:7], data[7:9], data[9:]):
            if part:
                sock.sendall(part)
                time.sleep(.005)
    def handle(self, raw, ctx):
        try:
            with ctx.wrap_socket(raw, server_side=True) as sock:
                self.sockets.append(sock)
                sock.settimeout(30)
                first = exact(sock, 8)
                if first[:4] == bytes.fromhex('fefcefbe'):
                    first += exact(sock, 332)
                    assert len(first) == 340 and first[80:89] == b'localhost'
                    self.send(sock, 0, b'\0'*4)
                    cmd, auth = receive(sock)
                    assert cmd == 1 and auth[:9] == b'localhost'
                    assert b'mockuser\0' in auth and b'mock%26%2B%25pass\0' in auth
                    time.sleep(self.auth_delay)
                    self.send(sock, 1, struct.pack('!II', 0 if self.auth_ok else 1, 0) + tlv(3, TOKEN))
                    if not self.auth_ok:
                        return
                    cmd, body = receive(sock)
                    assert cmd == 3 and body == TOKEN
                    self.send(sock, 3, b'\0'*4 + tlv(1, socket.inet_aton('10.90.0.2') + b'\x20') +
                              tlv(6, socket.inet_aton('198.51.100.0') + b'\x18'))
                    while True:
                        cmd, body = receive(sock)
                        assert cmd == 6 and body[:32] == TOKEN and len(body) == 36
                        if self.stalled != 'control':
                            self.send(sock, 6, b'')
                else:
                    assert first[:5] == MAGIC and first[5] == 0x64
                    assert exact(sock, 32) == TOKEN
                    self.send(sock, 0x64, b'\0')
                    if self.stalled == 'partial':
                        sock.sendall(frame(0x65)[:3])
                    if self.malformed:
                        sock.sendall(b'WRONGHDR')
                        time.sleep(.2)
                        return
                    while True:
                        cmd, body = receive(sock)
                        if self.stalled in ('data', 'partial'):
                            continue
                        if cmd == 0x65:
                            self.send(sock, cmd, b'')
                        else:
                            assert cmd == 0x66 and body[:8] == b'\0'*8
                            self.received.append(body[8:])
                            self.send(sock, cmd, body)
        except (EOFError, OSError, ssl.SSLError):
            pass
        except Exception as exc:
            self.errors.append(str(exc))
        finally:
            with self.closed_lock: self.closed += 1
    def close(self):
        self.stop.set()
        self.listener.close()
        for sock in self.sockets:
            try:
                sock.shutdown(socket.SHUT_RDWR)
            except OSError:
                pass
            sock.close()
        self.thread.join(1)

class Integration(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.tmp = tempfile.TemporaryDirectory(prefix='univpn-mock-')
        cls.root = pathlib.Path(cls.tmp.name)
        cls.cert, cls.key = cls.root/'server.pem', cls.root/'server.key'
        subprocess.run(['openssl','req','-x509','-newkey','rsa:2048','-nodes','-days','1',
                        '-subj','/CN=localhost','-addext','subjectAltName=IP:127.0.0.1,DNS:localhost,DNS:broker-only.invalid',
                        '-keyout',str(cls.key),'-out',str(cls.cert)], check=True,
                       stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        cls.shim = cls.root/'no-network.so'
        subprocess.run(['cc','-shared','-fPIC',str(pathlib.Path(__file__).with_name('univpn-no-network.c')),
                        '-o',str(cls.shim)],check=True)
        cls.ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        cls.ctx.load_cert_chain(cls.cert, cls.key)
    @classmethod
    def tearDownClass(cls):
        cls.tmp.cleanup()
    def run_client(self, gateway, packet_test=False, cafile=True, watchdog=False, preconnected=None, hostname=None, data_gateway=None):
        report = self.root/'result'
        report.unlink(missing_ok=True)
        script = self.root/'packet.py'
        script.write_text('''import os, socket, struct, time, pathlib
s=socket.socket(fileno=int(os.environ["VPNFD"]))
s.settimeout(8)
for proto in (6,17,1):
    packet=struct.pack("!BBHHHBBH4s4s",0x45,0,36,1,0,64,proto,0,socket.inet_aton("10.90.0.2"),socket.inet_aton("198.51.100.1"))+b"0123456789abcdef"
    s.send(packet)
    assert s.recv(65535)==packet
pathlib.Path(os.environ["MOCK_REPORT"]).write_text("PASS")
time.sleep(60)
''')
        cmd = [BINARY, '--no-proxy', '--verbose', '--protocol=univpn','--non-inter','--user=mockuser','--passwd-on-stdin',
               '--authgroup=localhost','--no-dtls','https://'+(hostname or '127.0.0.1')+':'+str(gateway.port)]
        if cafile:
            cmd += ['--cafile='+str(self.cert)]
        if packet_test:
            cmd += ['--script-tun','--script', shlex.quote(sys.executable)+' '+shlex.quote(str(script))]
        else:
            cmd += ['--authenticate']
        sockets = []
        if preconnected:
            sockets = [socket.create_connection(('127.0.0.1', g.port)) for g in (gateway, data_gateway or gateway)]
            control, data = sockets[0].fileno(), sockets[1].fileno()
            if preconnected == 'same': data = control
            if preconnected in ('udp','unconnected','listener'):
                invalid = socket.socket(socket.AF_INET, socket.SOCK_DGRAM if preconnected=='udp' else socket.SOCK_STREAM)
                if preconnected=='listener': invalid.bind(('127.0.0.1',0)); invalid.listen()
                sockets.append(invalid); data = invalid.fileno()
            if preconnected == 'closed': data = 1023
            if preconnected == 'stdio': data = 0
            if preconnected == 'file':
                file = open('/dev/null','rb'); sockets.append(file); data = file.fileno()
            if preconnected == 'wrongport':
                cmd = [arg.replace(':'+str(gateway.port),':'+str(gateway.port+1)) if arg.startswith('https://') else arg for arg in cmd]
            if preconnected == 'proxy': cmd += ['--proxy=http://127.0.0.1:9']
            if preconnected == 'protocol': cmd = [arg.replace('--protocol=univpn','--protocol=anyconnect') for arg in cmd]
            if preconnected == 'duplicate':
                duplicate = sockets[0].dup(); sockets.append(duplicate); data = duplicate.fileno()
            if preconnected == 'reverse':
                cmd += ['--meridian-data-fd='+str(data),'--meridian-control-fd='+str(control)]
            else:
                if preconnected != 'dataonly': cmd += ['--meridian-control-fd='+str(control)]
                if preconnected != 'partial': cmd += ['--meridian-data-fd='+str(data)]
            if preconnected=='repeated': cmd += ['--meridian-control-fd='+str(control)]
        try:
            proc = subprocess.Popen(cmd, stdin=subprocess.PIPE, stdout=subprocess.PIPE,
                                    stderr=subprocess.PIPE, env={**os.environ,'MOCK_REPORT':str(report), **({'LD_PRELOAD':str(self.shim)} if preconnected else {})},
                                    pass_fds=tuple(s.fileno() for s in sockets))
        finally:
            for sock in sockets: sock.close()
        proc.stdin.write(b'mock&+%pass\n'); proc.stdin.close(); proc.stdin = None
        try:
            if packet_test:
                end = time.monotonic()+(52 if watchdog else 15)
                while time.monotonic()<end and proc.poll() is None and (watchdog or not report.exists()):
                    time.sleep(.05)
                passed = report.exists()
                if proc.poll() is None:
                    proc.send_signal(signal.SIGINT)
                out, err = proc.communicate(timeout=8)
                return passed, proc.returncode, 'exit='+str(proc.returncode)+'\n'+out.decode(errors='replace')+err.decode(errors='replace')
            out, err = proc.communicate(timeout=40)
            return False, proc.returncode, 'exit='+str(proc.returncode)+'\n'+out.decode(errors='replace')+err.decode(errors='replace')
        finally:
            if proc.poll() is None:
                proc.kill(); proc.communicate()
    def test_ipv4_tcp_udp_icmp_frames(self):
        gateway = Gateway(self.ctx)
        try:
            passed, _, err = self.run_client(gateway, packet_test=True)
            self.assertTrue(passed, err)
            self.assertEqual([p[9] for p in gateway.received], [6,17,1])
            self.assertEqual(gateway.errors, [])
        finally:
            gateway.close()
    def test_preconnected_tls_and_ipv4(self):
        # This hostname is deliberately not resolvable: only inherited sockets
        # can reach the mock. Certificate hostname validation must still work.
        sni, sni_times = [], []
        ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        ctx.load_cert_chain(self.cert,self.key)
        ctx.set_servername_callback(lambda sock, name, ctx: (sni.append(name), sni_times.append(time.monotonic())) and None)
        gateway = Gateway(ctx, auth_delay=.3)
        try:
            passed, _, err = self.run_client(gateway, packet_test=True, preconnected='valid' , hostname='broker-only.invalid')
            self.assertTrue(passed, err)
            self.assertEqual(gateway.count, 2)
            self.assertEqual(sni, ['broker-only.invalid','broker-only.invalid'])
            self.assertGreater(sni_times[1]-sni_times[0], .25)
            self.assertEqual([p[9] for p in gateway.received], [6,17,1])
            self.assertEqual(gateway.errors, [])
        finally: gateway.close()
    def test_preconnected_wrong_tls_hostname(self):
        gateway = Gateway(self.ctx)
        try:
            _, code, err = self.run_client(gateway, preconnected='valid', hostname='wrong.invalid')
            self.assertEqual(code, 1, err)
            self.assertEqual(gateway.received, [])
            self.assertEqual(gateway.count, 2)
        finally: gateway.close()
    def test_preconnected_untrusted_certificate(self):
        gateway = Gateway(self.ctx)
        try:
            _, code, err = self.run_client(gateway, preconnected='valid', cafile=False)
            self.assertEqual(code, 1, err)
            self.assertEqual(gateway.count, 2)
        finally: gateway.close()
    def test_preconnected_invalid_pairs(self):
        for mode in ('same', 'duplicate', 'partial', 'closed', 'file', 'wrongport', 'proxy', 'protocol', 'udp', 'unconnected', 'listener', 'repeated', 'dataonly'):
            with self.subTest(mode=mode):
                gateway = Gateway(self.ctx)
                try:
                    _, code, err = self.run_client(gateway, preconnected=mode)
                    self.assertEqual(code, 1, err)
                    self.assertIn('Meridian', err)
                    self.assertEqual(gateway.received, [])
                finally: gateway.close()
    def test_preconnected_different_peer_port(self):
        gateway, other = Gateway(self.ctx), Gateway(self.ctx)
        try:
            _, code, err = self.run_client(gateway, preconnected='valid', data_gateway=other)
            self.assertEqual(code,1,err)
            self.assertIn('Invalid Meridian preconnected socket pair',err)
            self.assertEqual(gateway.received,[])
            self.assertEqual(other.received,[])
        finally: gateway.close(); other.close()
    def test_preconnected_reversed_options(self):
        gateway = Gateway(self.ctx)
        try:
            passed, _, err = self.run_client(gateway, packet_test=True, preconnected='reverse')
            self.assertTrue(passed,err)
        finally: gateway.close()
    def test_preconnected_auth_failure_closes_unused_data(self):
        gateway = Gateway(self.ctx, auth_ok=False)
        try:
            _, code, err = self.run_client(gateway, preconnected='valid')
            self.assertEqual(code,1,err)
            until=time.monotonic()+2
            while gateway.closed<2 and time.monotonic()<until: time.sleep(.01)
            self.assertEqual(gateway.closed,2,'control and unused data sockets must close')
        finally: gateway.close()
    def test_watchdog_silent_control(self):
        self.check_watchdog('control')
    def test_watchdog_silent_data(self):
        self.check_watchdog('data')
    def test_watchdog_incomplete_frame(self):
        self.check_watchdog('partial')
    def check_watchdog(self, mode):
        gateway = Gateway(self.ctx, stalled=mode)
        started = time.monotonic()
        try:
            _, code, err = self.run_client(gateway, packet_test=True, watchdog=True)
            self.assertEqual(code, 1, err)
            self.assertIn('watchdog expired', err)
            self.assertLess(time.monotonic()-started, 51)
            self.assertEqual(gateway.errors, [])
        finally:
            gateway.close()
    def test_authentication_success(self):
        gateway = Gateway(self.ctx)
        try:
            _, code, err = self.run_client(gateway)
            self.assertEqual(code, 0, err)
            self.assertEqual(gateway.errors, [])
        finally:
            gateway.close()
    def test_authentication_rejected(self):
        gateway = Gateway(self.ctx, auth_ok=False)
        try:
            _, code, err = self.run_client(gateway)
            self.assertEqual(code, 1)
            self.assertNotIn('mock&+%pass', err)
            self.assertNotIn('AddressSanitizer', err)
            self.assertEqual(gateway.errors, [])
        finally:
            gateway.close()
    def test_untrusted_certificate_rejected(self):
        gateway = Gateway(self.ctx)
        try:
            _, code, _ = self.run_client(gateway, cafile=False)
            self.assertEqual(code, 1)
            self.assertEqual(gateway.received, [])
        finally:
            gateway.close()
    def test_data_channel_must_match_control_identity(self):
        second_cert, second_key = self.root/'second.pem', self.root/'second.key'
        subprocess.run(['openssl','req','-x509','-newkey','rsa:2048','-nodes','-days','1',
                        '-subj','/CN=localhost','-addext','subjectAltName=IP:127.0.0.1,DNS:localhost,DNS:broker-only.invalid',
                        '-keyout',str(second_key),'-out',str(second_cert)],check=True,
                       stdout=subprocess.DEVNULL,stderr=subprocess.DEVNULL)
        second_ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        second_ctx.load_cert_chain(second_cert,second_key)
        bundle = self.root/'both-trusted.pem'
        bundle.write_bytes(self.cert.read_bytes()+second_cert.read_bytes())
        gateway = Gateway(self.ctx,data_ctx=second_ctx)
        original_cert = self.cert; self.cert = bundle
        try:
            passed, code, err = self.run_client(gateway,packet_test=True)
            self.assertFalse(passed)
            self.assertEqual(code,2,err)
            self.assertEqual(gateway.received,[])
            self.assertNotIn('AddressSanitizer',err)
        finally:
            self.cert = original_cert; gateway.close()
    def test_preconnected_data_channel_identity(self):
        second_cert, second_key = self.root/'second.pem', self.root/'second.key'
        subprocess.run(['openssl','req','-x509','-newkey','rsa:2048','-nodes','-days','1',
                        '-subj','/CN=localhost','-addext','subjectAltName=IP:127.0.0.1,DNS:localhost,DNS:broker-only.invalid',
                        '-keyout',str(second_key),'-out',str(second_cert)],check=True,
                       stdout=subprocess.DEVNULL,stderr=subprocess.DEVNULL)
        second_ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        second_ctx.load_cert_chain(second_cert,second_key)
        bundle = self.root/'both-trusted.pem'
        bundle.write_bytes(self.cert.read_bytes()+second_cert.read_bytes())
        gateway = Gateway(self.ctx,data_ctx=second_ctx)
        original_cert = self.cert; self.cert = bundle
        try:
            passed, code, err = self.run_client(gateway,packet_test=True,preconnected="valid",hostname="broker-only.invalid")
            self.assertFalse(passed)
            self.assertEqual(code,2,err)
            self.assertEqual(gateway.received,[])
            self.assertNotIn('AddressSanitizer',err)
        finally:
            self.cert = original_cert; gateway.close()
    def test_malformed_data_frame_terminates(self):
        gateway = Gateway(self.ctx, malformed=True)
        try:
            passed, code, err = self.run_client(gateway, packet_test=True)
            self.assertFalse(passed)
            self.assertEqual(code, 1)
            self.assertIn('invalid frame', err)
        finally:
            gateway.close()

if __name__ == '__main__':
    unittest.main(verbosity=2)
