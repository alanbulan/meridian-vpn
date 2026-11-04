import copy
import importlib.util
import json
from pathlib import Path
import tempfile
from types import SimpleNamespace
import unittest
from unittest.mock import patch

spec = importlib.util.spec_from_file_location('accept', Path(__file__).with_name('accept.py'))
accept = importlib.util.module_from_spec(spec)
spec.loader.exec_module(accept)


def fixtures():
    before = {
        'bus_id': 'a' * 32, 'nm_owner': ':1.7',
        'links': [{'ifname': 'lo'}, {'ifname': accept.BASE, 'linkinfo': {'info_kind': 'dummy'}}],
        'addresses': [{'ifname': 'lo'}, {'ifname': accept.BASE}],
        'routes4': [{'dst': '192.0.2.0/24', 'dev': accept.BASE}],
        'routes6': [], 'rules4': [], 'rules6': [],
        'connections': [{'uuid': 'base', 'type': 'dummy', 'device': accept.BASE}],
        'resolver_sha256': 'a' * 64,
    }
    active = copy.deepcopy(before)
    active['links'].append({'ifname': accept.INTERFACE, 'linkinfo': {'info_kind': 'tun', 'info_data': {'type': 'tun'}}})
    active['addresses'].append({'ifname': accept.INTERFACE,
        'addr_info': [{'family': 'inet', 'local': accept.ADDRESS, 'prefixlen': 30}]})
    active['routes4'].append({'dst': accept.ROUTE, 'dev': accept.INTERFACE})
    active['connections'].append({'uuid': accept.UUID, 'type': 'vpn', 'device': accept.INTERFACE})
    return before, active


class EvidenceTests(unittest.TestCase):
    def test_expected_observations(self):
        before, active = fixtures()
        accept.check_baseline(before)
        accept.check_active(before, active)
        accept.check_restored(before, copy.deepcopy(before))

    def test_baseline_rejections(self):
        for change in (
            lambda s: s['links'].append({'ifname': 'eth0'}),
            lambda s: s['links'][1]['linkinfo'].update(info_kind='veth'),
            lambda s: s['routes4'].append({'dst': 'default', 'dev': accept.BASE}),
            lambda s: s['routes6'].append({'dst': '::/0', 'dev': accept.BASE}),
            lambda s: s['connections'][0].update(type='vpn'),
            lambda s: s['connections'].clear(),
        ):
            before, _ = fixtures()
            change(before)
            with self.assertRaises(accept.Rejected):
                accept.check_baseline(before)

    def test_active_rejections(self):
        changes = {
            'owner changed': lambda s: s.update(nm_owner=':1.8'),
            'bus changed': lambda s: s.update(bus_id='b' * 32),
            'local offered route': lambda s: s['routes4'][-1].update(type='local', table='local'),
            'resolver': lambda s: s.update(resolver_sha256='b' * 64),
            'rules': lambda s: s['rules4'].append({'table': 100}),
            'ipv6': lambda s: s['routes6'].append({'dst': '::/1'}),
            'missing route': lambda s: s['routes4'].pop(),
            'default route': lambda s: s['routes4'].append({'dst': 'default', 'dev': accept.INTERFACE}),
            'gateway': lambda s: s['routes4'][-1].update(gateway='198.18.0.1'),
            'foreign table': lambda s: s['routes4'][-1].update(table=100),
            'extra attribute': lambda s: s['routes4'][-1].update(nh_id=4),
            'wrong address': lambda s: s['addresses'][-1]['addr_info'][0].update(local='198.18.0.1'),
            'extra address': lambda s: s['addresses'][-1]['addr_info'].append({'family': 'inet6'}),
            'wrong NM UUID': lambda s: s['connections'][-1].update(uuid='foreign'),
            'missing base': lambda s: s['connections'].pop(0),
            'TAP device': lambda s: s['links'][-1]['linkinfo']['info_data'].update(type='tap'),
            'missing TUN type': lambda s: s['links'][-1]['linkinfo'].pop('info_data'),
            'not TUN': lambda s: s['links'][-1]['linkinfo'].update(info_kind='dummy'),
            'parent changed': lambda s: s['links'][1].update(mtu=1200),
            'removed baseline route': lambda s: s['routes4'].pop(0),
        }
        for name, change in changes.items():
            with self.subTest(name=name):
                before, active = fixtures()
                change(active)
                with self.assertRaises(accept.Rejected):
                    accept.check_active(before, active)

    def test_route_destination_type_table_tuple(self):
        for destination, kind, table in (
            (accept.ROUTE, 'local', 'local'),
            (accept.ROUTE, 'broadcast', 'local'),
            ('198.18.0.0/30', 'local', 'local'),
            ('198.18.0.0/30', 'broadcast', 'local'),
            (accept.ADDRESS, 'unicast', 'main'),
            ('198.18.0.3', 'unicast', 'main'),
            (accept.ADDRESS, 'local', 'main'),
        ):
            before, active = fixtures()
            active['routes4'].append({'dst': destination, 'dev': accept.INTERFACE,
                                      'type': kind, 'table': table})
            with self.subTest(destination=destination, kind=kind, table=table):
                with self.assertRaises(accept.Rejected):
                    accept.check_active(before, active)
        before, active = fixtures()
        for destination, kind, table in (
            ('198.18.0.0/30', 'unicast', 254),
            (accept.ADDRESS, 'local', 255),
            ('198.18.0.0', 'broadcast', 'local'),
            ('198.18.0.3', 'broadcast', 'local'),
        ):
            active['routes4'].append({'dst': destination, 'dev': accept.INTERFACE,
                                      'type': kind, 'table': table})
        accept.check_active(before, active)

    def test_cleanup_must_restore_every_field(self):
        before, active = fixtures()
        for key in before:
            after = copy.deepcopy(before)
            after[key] = 'different'
            with self.subTest(key=key), self.assertRaises(accept.Rejected):
                accept.check_restored(before, after)
        with self.assertRaises(accept.Rejected):
            accept.check_restored(before, active)

    def test_counters_and_lifetimes_only_are_normalized(self):
        before, _ = fixtures()
        before['links'][0]['stats64'] = {'rx': 1}
        before['addresses'][0]['addr_info'] = [{'valid_life_time': 100, 'scope': 'host'}]
        result = accept.stable_snapshot(before)
        self.assertNotIn('stats64', result['links'][0])
        self.assertEqual(result['addresses'][0]['addr_info'], [{'scope': 'host'}])
        self.assertIn('stats64', before['links'][0])

    def test_no_command_before_opt_in(self):
        calls = []
        args = SimpleNamespace(accept='no', boot_id='wrong')
        with patch.dict('os.environ', {}, clear=True):
            with self.assertRaises(accept.Rejected):
                accept.preflight(args, lambda command: calls.append(command))
        self.assertEqual(calls, [])

    def test_preflight_rejects_wrong_uid_boot_vm_and_version(self):
        args = SimpleNamespace(accept=accept.TOKEN, boot_id='expected')
        for failure in ('uid', 'boot', 'container', 'vm', 'nested', 'client', 'daemon', 'asleep'):
            with self.subTest(failure=failure):
                def command(argv):
                    if '--container' in argv:
                        return 'docker' if failure == 'container' else 'none'
                    if 'systemd-detect-virt' in argv[0]:
                        return 'docker' if failure == 'vm' else 'kvm'
                    if '--version' in argv:
                        return 'nmcli tool, version 1.50.0' if failure == 'client' else 'nmcli tool, version 1.52.1'
                    if 'VERSION' in argv:
                        return '1.50.0' if failure == 'daemon' else '1.52.1'
                    return 'asleep' if failure == 'asleep' else 'connected'
                def readlink(path):
                    return 'different' if failure == 'nested' and '/self/' in path else 'net:[1]'
                with patch.dict('os.environ', {'MERIDIAN_REAL_NM_VM': '1'}, clear=True), \
                     patch.object(accept.os, 'getuid', return_value=1000 if failure == 'uid' else 0), \
                     patch.object(accept.os, 'geteuid', return_value=0), \
                     patch.object(Path, 'read_text', return_value='wrong' if failure == 'boot' else 'expected'), \
                     patch.object(accept.os, 'readlink', side_effect=readlink):
                    with self.assertRaises(accept.Rejected):
                        accept.preflight(args, command)

    def test_preflight_accepts_noncontainer_full_vm(self):
        args = SimpleNamespace(accept=accept.TOKEN, boot_id='expected')
        calls = []
        def command(argv):
            calls.append(argv)
            if '--container' in argv:
                return 'none'
            if '--vm' in argv:
                return 'kvm'
            if '--version' in argv:
                return 'nmcli tool, version 1.52.1'
            if 'VERSION' in argv:
                return '1.52.1'
            return 'connected'
        with patch.dict('os.environ', {'MERIDIAN_REAL_NM_VM': '1'}, clear=True), \
             patch.object(accept.os, 'getuid', return_value=0), \
             patch.object(accept.os, 'geteuid', return_value=0), \
             patch.object(Path, 'read_text', return_value='expected'), \
             patch.object(accept.os, 'readlink', return_value='net:[1]'):
            self.assertEqual(accept.preflight(args, command), 'expected')
        self.assertEqual(calls[0][-1], '--container')
        self.assertEqual(calls[1][-1], '--vm')

    def test_container_absence_exit_code_is_narrowly_accepted(self):
        import subprocess
        argv = ['/usr/bin/systemd-detect-virt', '--container']
        for code, output, accepted in [(1, b'none\n', True), (0, b'docker\n', True),
                                       (2, b'none\n', False), (1, b'error\n', False)]:
            result = subprocess.CompletedProcess(argv, code, output, b'')
            with patch.object(accept.subprocess, 'run', return_value=result):
                if accepted:
                    self.assertEqual(accept.run(argv), output.decode())
                else:
                    with self.assertRaises(subprocess.CalledProcessError):
                        accept.run(argv)
        result = subprocess.CompletedProcess(['other'], 1, b'none\n', b'')
        with patch.object(accept.subprocess, 'run', return_value=result):
            with self.assertRaises(subprocess.CalledProcessError):
                accept.run(['other'])

    def test_offline_audit_and_reboot_rejection(self):
        before, active = fixtures()
        with tempfile.TemporaryDirectory() as tmp:
            directory = Path(tmp)
            accept.write(directory / 'admission.json', {'boot_id': 'same'})
            for phase, value in [('before', before), ('active', active), ('after', before)]:
                accept.write(directory / (phase + '.json'), {'boot_id': 'same', 'network': value})
            self.assertFalse(accept.audit(directory)['production_acceptance'])
            (directory / 'after.json').write_text(json.dumps({'boot_id': 'new', 'network': before}))
            with self.assertRaises(accept.Rejected):
                accept.audit(directory)


if __name__ == '__main__':
    unittest.main()
