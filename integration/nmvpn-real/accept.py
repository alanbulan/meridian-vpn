#!/usr/bin/env python3
"""VM-only acceptance orchestrator. Never invoked by normal builds or CI.

Captures observations only; starting/stopping the real service is a separate
reviewed VM action. No fake authority, network setup or driver is supplied.
"""
import argparse
import hashlib
import json
import os
import re
from pathlib import Path
import stat
import subprocess

TOKEN = 'I_ACCEPT_NETWORK_CHANGES_IN_THIS_DISPOSABLE_VM'
INTERFACE = 'meridian-test0'
BASE = 'meridian-base0'
ADDRESS = '198.18.0.2'
ROUTE = '198.19.0.0/24'
UUID = '7bbd9315-f867-454e-abf1-ff801794604b'


class Rejected(RuntimeError):
    pass


def require(value, reason):
    if not value:
        raise Rejected(reason)


def run(argv):
    result = subprocess.run(argv, stdin=subprocess.DEVNULL, capture_output=True,
                            timeout=15, check=False, env=environment())
    # systemd-detect-virt reports successful absence with status 1, not 0.
    absent_container = (argv == ['/usr/bin/systemd-detect-virt', '--container']
                        and result.returncode == 1 and result.stdout.strip() == b'none')
    if not absent_container:
        result.check_returncode()
    require(len(result.stdout) <= 1024 * 1024, 'command evidence exceeds limit')
    return result.stdout.decode('utf-8')


def environment():
    # Never inherit a session bus, proxy, shell startup or language overrides.
    return {'PATH': '/usr/sbin:/usr/bin:/sbin:/bin', 'LANG': 'C', 'LC_ALL': 'C',
            'HOME': '/root'}


def canonical(value):
    if isinstance(value, list):
        return sorted((canonical(v) for v in value), key=lambda v: json.dumps(v, sort_keys=True))
    if isinstance(value, dict):
        return {k: canonical(v) for k, v in sorted(value.items())}
    return value


def stable_snapshot(snapshot):
    # Drop counters/lifetimes only. Preserve every other observed field; unknown
    # additive state can conservatively fail equality rather than imply absence.
    result = json.loads(json.dumps(snapshot))
    for link in result['links']:
        for key in ('stats64', 'stats'):
            link.pop(key, None)
    for link in result['addresses']:
        for address in link.get('addr_info', []):
            for key in ('valid_life_time', 'preferred_life_time'):
                address.pop(key, None)
    return canonical(result)


def snapshot(command=run, resolver_path=Path('/etc/resolv.conf')):
    with resolver_path.open('rb') as source:
        resolver = source.read(65537)
    require(len(resolver) <= 65536, 'resolver evidence exceeds limit')
    bus_id = command(['/usr/bin/busctl', '--system', 'call', 'org.freedesktop.DBus',
                      '/org/freedesktop/DBus', 'org.freedesktop.DBus', 'GetId']).strip()
    owner = command(['/usr/bin/busctl', '--system', 'call', 'org.freedesktop.DBus',
                     '/org/freedesktop/DBus', 'org.freedesktop.DBus', 'GetNameOwner',
                     's', 'org.freedesktop.NetworkManager']).strip()
    require(re.fullmatch(r's "[a-f0-9]{32}"', bus_id), 'invalid bus ID')
    require(re.fullmatch(r's ":[0-9]+\.[0-9]+"', owner), 'invalid NM unique owner')
    require(command(['/usr/bin/busctl', '--system', 'call', 'org.freedesktop.DBus',
                     '/org/freedesktop/DBus', 'org.freedesktop.DBus',
                     'GetConnectionUnixUser', 's', owner[3:-1]]).strip() == 'u 0',
            'NM bus owner is not root')
    connections = []
    text = command(['/usr/bin/nmcli', '--terse', '--escape', 'no', '--fields',
                    'UUID,TYPE,DEVICE', 'connection', 'show', '--active'])
    for line in text.splitlines():
        fields = line.split(':')
        require(len(fields) == 3, 'ambiguous active-connection evidence')
        connections.append(dict(zip(('uuid', 'type', 'device'), fields)))
    return stable_snapshot({
        'bus_id': bus_id, 'nm_owner': owner,
        'links': json.loads(command(['ip', '-j', '-d', 'link', 'show'])),
        'addresses': json.loads(command(['ip', '-j', 'address', 'show'])),
        'routes4': json.loads(command(['ip', '-j', '-4', 'route', 'show', 'table', 'all'])),
        'routes6': json.loads(command(['ip', '-j', '-6', 'route', 'show', 'table', 'all'])),
        'rules4': json.loads(command(['ip', '-j', '-4', 'rule', 'show'])),
        'rules6': json.loads(command(['ip', '-j', '-6', 'rule', 'show'])),
        'connections': connections,
        'resolver_sha256': hashlib.sha256(resolver).hexdigest(),
    })


def check_baseline(s):
    require({v['ifname'] for v in s['links']} == {'lo', BASE},
            'only loopback and the preprovisioned synthetic parent may exist')
    base = next(v for v in s['links'] if v['ifname'] == BASE)
    require(base.get('linkinfo', {}).get('info_kind') == 'dummy', 'parent must be a dummy device')
    require(all(r.get('dst') not in ('default', '0.0.0.0/0', '::/0')
                for key in ('routes4', 'routes6') for r in s[key]), 'default route is forbidden')
    require(all(c['type'] != 'vpn' and c['uuid'] != UUID for c in s['connections']),
            'existing VPN or fixture generation is forbidden')
    require(any(c['device'] == BASE for c in s['connections']), 'synthetic NM parent must be active')
    # This is an environment safety guard, not initial-host-namespace proof.
    require(all(r.get('dev') in ('lo', BASE, None) for r in s['routes4'] + s['routes6']),
            'foreign route device in baseline')


def check_active(before, active):
    for key in ('bus_id', 'nm_owner', 'rules4', 'rules6', 'routes6', 'resolver_sha256'):
        require(active[key] == before[key], key + ' changed')
    extras = [c for c in active['connections'] if c not in before['connections']]
    require(extras == [{'uuid': UUID, 'type': 'vpn', 'device': INTERFACE}],
            'exact NM VPN activation not independently observed')
    require(all(c in active['connections'] for c in before['connections']), 'base activation disappeared')
    links = [v for v in active['links'] if v['ifname'] == INTERFACE]
    require(len(links) == 1 and links[0].get('linkinfo', {}).get('info_kind') == 'tun'
            and links[0].get('linkinfo', {}).get('info_data', {}).get('type') == 'tun',
            'one real TUN link is required')
    require([v for v in active['links'] if v['ifname'] != INTERFACE] == before['links'],
            'baseline link state changed')
    addresses = [v for v in active['addresses'] if v['ifname'] == INTERFACE]
    require(len(addresses) == 1, 'TUN address evidence missing')
    infos = addresses[0].get('addr_info', [])
    require(len(infos) == 1 and infos[0].get('family') == 'inet'
            and infos[0].get('local') == ADDRESS and infos[0].get('prefixlen') == 30,
            'unexpected tunnel addresses or IPv6')
    require([v for v in active['addresses'] if v['ifname'] != INTERFACE] == before['addresses'],
            'baseline addresses changed')
    require(all(r in active['routes4'] for r in before['routes4']), 'baseline route disappeared')
    routes = [r for r in active['routes4'] if r not in before['routes4']]
    require(any(r.get('dst') == ROUTE and r.get('type', 'unicast') == 'unicast'
                and r.get('table', 'main') in ('main', 254) for r in routes),
            'offered main-table unicast route missing')
    # Check semantic tuples, not independent value allowlists. A local or
    # broadcast route to an offered subnet is not a usable split VPN route.
    allowed = {
        (ROUTE, 'unicast', 'main'), ('198.18.0.0/30', 'unicast', 'main'),
        (ADDRESS, 'local', 'local'), (ADDRESS + '/32', 'local', 'local'),
        ('198.18.0.0', 'broadcast', 'local'), ('198.18.0.0/32', 'broadcast', 'local'),
        ('198.18.0.3', 'broadcast', 'local'), ('198.18.0.3/32', 'broadcast', 'local'),
    }
    keys = {'dst', 'dev', 'protocol', 'scope', 'prefsrc', 'metric', 'flags', 'table', 'type'}
    for route in routes:
        table = route.get('table', 'main')
        table = {254: 'main', 255: 'local'}.get(table, table)
        identity = (route.get('dst'), route.get('type', 'unicast'), table)
        require(set(route) <= keys and route.get('dev') == INTERFACE
                and identity in allowed and not route.get('flags')
                and route.get('prefsrc', ADDRESS) == ADDRESS,
                'unexpected route, gateway, attribute or policy table')


def check_restored(before, after):
    require(before == after, 'network/resolver/NM baseline was not restored exactly')


def preflight(args, command=run):
    require(args.accept == TOKEN and os.environ.get('MERIDIAN_REAL_NM_VM') == '1', 'both explicit opt-ins required')
    require(os.getuid() == 0 and os.geteuid() == 0, 'disposable VM root required')
    boot = Path('/proc/sys/kernel/random/boot_id').read_text().strip()
    require(args.boot_id == boot, 'explicit current VM boot ID must match')
    # A container hosted by a VM can still make --vm succeed. Reject it
    # independently before relying on the full-VM result.
    require(command(['/usr/bin/systemd-detect-virt', '--container']).strip() == 'none',
            'containers nested inside VMs are forbidden')
    require(command(['/usr/bin/systemd-detect-virt', '--vm']).strip() in
            ('kvm', 'qemu', 'vmware', 'microsoft', 'oracle', 'xen', 'parallels', 'bhyve'),
            'recognized full VM required; containers are not accepted')
    require(os.readlink('/proc/self/ns/net') == os.readlink('/proc/1/ns/net'), 'unexpected nested network namespace')
    require(command(['/usr/bin/nmcli', '--version']).strip() == 'nmcli tool, version 1.52.1', 'only reviewed NM 1.52.1 supported')
    require(command(['/usr/bin/nmcli', '--terse', '--fields', 'VERSION', 'general']).strip() == '1.52.1', 'daemon/client version mismatch')
    require(command(['/usr/bin/nmcli', '--terse', '--fields', 'STATE', 'general']).strip() != 'asleep', 'NM daemon unavailable')
    return boot


def write(path, data):
    with path.open('x', encoding='utf-8') as target:
        json.dump(data, target, indent=2, sort_keys=True)
        target.write('\n')


def audit(directory):
    admission = json.loads((directory / 'admission.json').read_text())
    samples = [json.loads((directory / (phase + '.json')).read_text())
               for phase in ('before', 'active', 'after')]
    require(all(s['boot_id'] == admission['boot_id'] for s in samples), 'VM rebooted between phases')
    before, active, after = [s['network'] for s in samples]
    check_baseline(before)
    check_active(before, active)
    check_restored(before, after)
    return {'version': 1, 'observations_match': True,
            'scope': 'three sequential NM/kernel/resolv.conf samples only',
            'production_acceptance': False}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--accept')
    parser.add_argument('--boot-id')
    parser.add_argument('--phase', choices=('before', 'active', 'after', 'audit'), required=True)
    parser.add_argument('--evidence', required=True)
    args = parser.parse_args()
    os.umask(0o077)
    directory = Path(args.evidence)
    require(directory.is_absolute(), 'absolute evidence directory required')
    if args.phase == 'audit':
        # Offline only. Inputs are evidence claims, not authenticated host proof.
        print(json.dumps(audit(directory), sort_keys=True))
        return
    boot = preflight(args)
    for parent in directory.parents:
        st = parent.lstat()
        require(stat.S_ISDIR(st.st_mode) and st.st_uid == 0 and not st.st_mode & 0o022,
                'capture evidence ancestors must be root-owned and not group/world writable')
    if args.phase == 'before':
        directory.mkdir(mode=0o700, parents=False, exist_ok=False)
        write(directory / 'admission.json', {'version': 1, 'boot_id': boot,
              'nm_version': '1.52.1', 'production_acceptance': False})
    else:
        st = directory.lstat()
        require(stat.S_ISDIR(st.st_mode) and st.st_uid == 0 and st.st_mode & 0o077 == 0,
                'existing private root-owned evidence directory required')
        admission = json.loads((directory / 'admission.json').read_text())
        require(admission['boot_id'] == boot, 'VM boot identity changed')
    state = snapshot()
    # Store failed observations too. Never repair or delete network state.
    write(directory / (args.phase + '.json'), {'boot_id': boot, 'network': state})
    if args.phase == 'before':
        check_baseline(state)
    elif args.phase == 'active':
        before = json.loads((directory / 'before.json').read_text())['network']
        check_active(before, state)
    else:
        print(json.dumps(audit(directory), sort_keys=True))


if __name__ == '__main__':
    try:
        main()
    except Exception as error:
        print('REJECTED:', type(error).__name__, str(error))
        raise SystemExit(1)
