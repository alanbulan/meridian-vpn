#!/usr/bin/env python3
# Modified version for Meridian; publication notices added 2026-11-03.
# This file differs from pinned upstream OpenConnect through the documented
# UniVPN and Meridian patch series. Original authorship and license notices
# remain unchanged. Earlier patch dates are preserved where recorded; this
# date identifies the notice addition, not an invented original change date.
"""Native inherited packet channel: real local IPC/TLS, no host TUN/netlink."""
import array, importlib.util, json, os, pathlib, select, signal, socket, struct, subprocess, sys, time, unittest
spec=importlib.util.spec_from_file_location('mock',pathlib.Path(__file__).with_name('univpn-integration.py'))
mock=importlib.util.module_from_spec(spec);spec.loader.exec_module(mock)
NONCE='0123456789abcdef0123456789abcdef'

def checksum(data):
    if len(data)%2:data+=b'\0'
    value=sum(struct.unpack('!%dH'%(len(data)//2),data))
    while value>>16:value=(value&65535)+(value>>16)
    return (~value)&65535

def packet():
    udp=struct.pack('!HHHH',10000,20000,12,0)+b'test'
    header=struct.pack('!BBHHHBBH4s4s',0x45,0,32,1,0x4000,64,17,0,socket.inet_aton('10.90.0.2'),socket.inet_aton('198.51.100.1'))
    return header[:10]+struct.pack('!H',checksum(header))+header[12:]+udp

class Packet(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        # No named socket/listener. If unsupported/denied, fail this class once.
        a,b=socket.socketpair(socket.AF_UNIX,socket.SOCK_SEQPACKET);a.close();b.close()
        mock.Integration.setUpClass()
        cls.guard=mock.Integration.root/'no-host.so'
        subprocess.run(['cc','-shared','-fPIC',str(pathlib.Path(__file__).with_name('univpn-no-host-network.c')),'-ldl','-o',str(cls.guard)],check=True)
    @classmethod
    def tearDownClass(cls):mock.Integration.tearDownClass()
    def start(self,auth_ok=True,missing=None):
        self.gateway=mock.Gateway(mock.Integration.ctx,auth_ok=auth_ok)
        self.packet,child=socket.socketpair(socket.AF_UNIX,socket.SOCK_SEQPACKET)
        self.packet.settimeout(5)
        self.read,write=os.pipe();self.pending=b''
        sockets=[socket.create_connection(('127.0.0.1',self.gateway.port)) for _ in range(2)]
        cmd=[mock.BINARY,'--protocol=univpn','--no-proxy','--no-dtls','--non-inter','--user=mockuser','--passwd-on-stdin','--authgroup=localhost','--cafile='+str(mock.Integration.cert),'--meridian-packet-fd='+str(child.fileno())]
        if missing!='session':cmd+=['--meridian-session-fd='+str(write),'--meridian-session-id='+NONCE]
        if missing!='transport':cmd+=['--meridian-control-fd='+str(sockets[0].fileno()),'--meridian-data-fd='+str(sockets[1].fileno())]
        if missing=='script':cmd+=['--script-tun','--script=/bin/false']
        cmd+=['https://broker-only.invalid:'+str(self.gateway.port)]
        try:
            self.proc=subprocess.Popen(cmd,stdin=subprocess.PIPE,stdout=subprocess.PIPE,stderr=subprocess.PIPE,
              pass_fds=(write,child.fileno(),*(s.fileno() for s in sockets)),env={**os.environ,'LD_PRELOAD':str(self.guard),**({'UNIVPN_TEST_NAMED_LOCAL':'1'} if missing=='namedlocal' else {})})
        finally:
            child.close();os.close(write)
            for s in sockets:s.close()
        self.proc.stdin.write(b'mock&+%pass\n');self.proc.stdin.close();self.proc.stdin=None
    def record(self):
        until=time.monotonic()+8
        while b'\n' not in self.pending:
            left=until-time.monotonic()
            self.assertGreater(left,0,'native record timeout')
            self.assertTrue(select.select([self.read],[],[],left)[0],'native record timeout')
            part=os.read(self.read,32768)
            self.assertTrue(part,'native pipe closed before record')
            self.pending+=part;self.assertLessEqual(len(self.pending),32768)
        line,self.pending=self.pending.split(b'\n',1);return json.loads(line)
    def offer(self):
        r=self.record();self.assertEqual(r['version'],2);self.assertEqual(r['event'],'offer');self.assertEqual(r['session'],NONCE)
        self.assertEqual(set(r),{'version','event','session','addresses','routes','dns','endpoint'})
        self.assertEqual(r['addresses'],['10.90.0.2/32']);self.assertEqual(r['endpoint'],'127.0.0.1')
    def ended(self):
        out,err=self.proc.communicate(timeout=8)
        self.assertNotEqual(self.proc.returncode,-signal.SIGABRT,'forbidden host operation: '+err.decode(errors='replace'))
        self.assertEqual(self.record(),{'version':2,'event':'relay-closed','session':NONCE})
        self.assertEqual(os.read(self.read,1),b'')
    def tearDown(self):
        if hasattr(self,'proc') and self.proc.poll() is None:self.proc.kill();self.proc.communicate()
        if hasattr(self,'packet'):self.packet.close()
        if hasattr(self,'read'):os.close(self.read)
        if hasattr(self,'gateway'):self.gateway.close()
    def test_offer_and_packets(self):
        self.start();self.offer();p=packet();self.packet.send(p);self.assertEqual(self.packet.recv(65536),p)
        self.proc.send_signal(signal.SIGINT);self.ended();self.assertEqual(self.gateway.errors,[])
    def test_peer_close_is_terminal(self):
        self.start();self.offer();self.packet.close();self.ended()
    def test_oversized_message_is_terminal(self):
        self.start();self.offer();self.packet.send(b'x'*2000);self.ended();self.assertEqual(self.gateway.received,[])
    def test_zero_message_is_terminal(self):
        self.start();self.offer();self.packet.send(b'');self.ended();self.assertEqual(self.gateway.received,[])
    def test_ancillary_rights_rejected(self):
        self.start();self.offer()
        with open('/dev/null','rb') as f:self.packet.sendmsg([packet()],[(socket.SOL_SOCKET,socket.SCM_RIGHTS,array.array('i',[f.fileno()]))])
        self.ended();self.assertEqual(self.gateway.received,[])
    def test_auth_failure_never_claims_interface_cleanup(self):
        self.start(auth_ok=False);self.ended();self.assertEqual(self.gateway.received,[])
    def test_missing_session_rejected(self):
        self.start(missing='session');_,err=self.proc.communicate(timeout=8);self.assertEqual(self.proc.returncode,1,err);self.assertEqual(self.gateway.received,[])
    def test_missing_transport_rejected(self):
        self.start(missing='transport');_,err=self.proc.communicate(timeout=8);self.assertEqual(self.proc.returncode,1,err);self.assertEqual(self.gateway.received,[])
    def test_named_local_socket_rejected_without_binding(self):
        self.start(missing='namedlocal');_,err=self.proc.communicate(timeout=8);self.assertEqual(self.proc.returncode,1,err);self.assertEqual(self.gateway.received,[])
    def test_script_mode_rejected(self):
        self.start(missing='script');_,err=self.proc.communicate(timeout=8);self.assertEqual(self.proc.returncode,1,err);self.assertEqual(self.gateway.received,[])
if __name__=='__main__':unittest.main(verbosity=2)
