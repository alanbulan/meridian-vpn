#!/usr/bin/env python3
"""Run opt-in localhost fixtures; never install dependencies or activate a VPN."""
import argparse
import json
import os
from pathlib import Path
import subprocess
import sys

ROOT = Path(__file__).resolve().parents[2]
AUTH_TESTS = {
    'TestRealOpenConnect' + name for name in (
        'AuthenticationOnly', 'RejectsBadPassword', 'RejectsUntrustedCertificate',
        'Cancellation', 'ClientCertificate', 'RejectsClientCertificate',
        'RejectsKeyPassphrase', 'ClientCertificateCancellation', 'PKCS12',
        'EncryptedPKCS8')
} | {
    'TestRealMFA' + name for name in (
        'ChallengeRetry', 'RejectsUntrustedCertificate', 'CancelPrompt',
        'RoundBound', 'RejectsUnsupportedForm', 'ClientCertificate',
        'HostnameResolution', 'ConfiguredGroup')
}
CLI_AUTH_TESTS = {'TestTerminalPTY', 'TestRealCLIMFAChallengeRetry', 'TestRealCLIMFACancelPrompt'}
AUTH_REQUIRED = ({('mygo-vpn/internal/core', test) for test in AUTH_TESTS}
                 | {('mygo-vpn/cmd/meridianctl', test) for test in CLI_AUTH_TESTS})
AUTH_PACKAGES = {package for package, _ in AUTH_REQUIRED}
NATIVE_TEST_FILES = (
    'univpn-integration.py', 'univpn-codec.c', 'univpn-hook.c',
    'univpn-session.c', 'univpn-session-integration.py', 'univpn-fd-session.c',
    'univpn-fd-session.py', 'univpn-fd-cleanup.c', 'univpn-packet-integration.py',
)


def verify_auth_results(path):
    """No green result from missing, skipped, failed, or truncated fixtures."""
    passed = set()
    packages_passed = set()
    with path.open(encoding='utf-8') as stream:
        for line in stream:
            event = json.loads(line)
            action, test = event.get('Action'), event.get('Test')
            if action in ('skip', 'fail'):
                raise ValueError('authentication fixture skipped or failed: ' + (test or 'package'))
            if action == 'pass':
                if test:
                    passed.add((event.get('Package'), test))
                elif event.get('Package') in AUTH_PACKAGES:
                    packages_passed.add(event['Package'])
    missing = AUTH_REQUIRED - passed
    if missing or packages_passed != AUTH_PACKAGES:
        raise ValueError('incomplete authentication evidence; missing: ' + ', '.join(package + ':' + test for package, test in sorted(missing)))
    return len(AUTH_REQUIRED)


def command(args, log, cwd=ROOT, env=None):
    print('+ ' + ' '.join(map(str, args)), flush=True)
    with log.open('w', encoding='utf-8') as output:
        subprocess.run(list(map(str, args)), cwd=cwd, env=env, stdout=output,
                       stderr=subprocess.STDOUT, check=True, timeout=1200)


def auth(args, reports):
    env = os.environ.copy()
    for key in ('MERIDIAN_OPENCONNECT_TEST_BINARY', 'MERIDIAN_MFA_HELPER_TEST_BINARY'):
        path = Path(env.get(key, ''))
        if not path.is_absolute() or not path.is_file() or not os.access(path, os.X_OK):
            raise ValueError(key + ' must name a trusted, executable absolute path')
    env['CGO_ENABLED'] = '0'
    log = reports / 'auth.jsonl'
    # stderr is separate so build failures cannot corrupt the JSON evidence.
    with log.open('w', encoding='utf-8') as output, (reports / 'auth-stderr.log').open('w') as errors:
        subprocess.run([args.go, 'test', '-count=1', '-timeout=10m', '-json',
                        './internal/core', './cmd/meridianctl', '-run',
                        '^(TestRealOpenConnect|TestRealMFA|TestRealCLIMFA|TestTerminalPTY)'],
                       cwd=ROOT, env=env, stdout=output, stderr=errors,
                       check=True, timeout=660)
    count = verify_auth_results(log)
    return {'status': 'passed', 'required_top_level_tests': count,
            'scope': 'synthetic localhost TLS authentication only; no VPN tunnel'}


def native(args, reports):
    archive = ROOT / 'integration/univpn-native/source/openconnect-upstream.tar.gz'
    if not archive.is_file():
        raise ValueError('bundled native archive missing; network download is not allowed by this runner')
    destination = args.native_build.resolve()
    if destination.exists():
        raise ValueError('native build destination must be fresh')
    command([sys.executable, ROOT / 'integration/univpn-native/scripts/prepare_native.py',
             '--archive', archive, '--destination', destination], reports / 'native-prepare.log')
    # The historical build script uses conditional test-file checks. Fail before
    # running it if a fixture disappeared, rather than silently reducing coverage.
    for name in NATIVE_TEST_FILES:
        if not (destination / 'tests' / name).is_file():
            raise ValueError('required native fixture missing: ' + name)
    command(['sh', ROOT / 'integration/univpn-native/scripts/build_native.sh'],
            reports / 'native-build-tests.log', cwd=destination)
    return {'status': 'passed', 'scope': 'loopback TLS, socket packets and syscall-wrapped tests; no kernel TUN',
            'limitation': 'not production sandbox, corporate gateway or host route/DNS acceptance'}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('suite', choices=('auth', 'native'))
    parser.add_argument('--reports', type=Path, required=True)
    parser.add_argument('--native-build', type=Path, default=ROOT / 'build/loopback-native')
    parser.add_argument('--go', default=os.environ.get('GO', 'go'))
    args = parser.parse_args()
    if sys.platform != 'linux':
        parser.error('these opt-in fixtures require Linux')
    if os.geteuid() == 0:
        parser.error('run fixtures as an unprivileged user, never root')
    reports = args.reports.resolve()
    reports.mkdir(parents=True, exist_ok=True)
    summary = {'suite': args.suite, 'status': 'failed', 'live_vpn_acceptance': False}
    try:
        summary.update((auth if args.suite == 'auth' else native)(args, reports))
    except (OSError, ValueError, subprocess.SubprocessError) as error:
        summary['error'] = str(error)
        print(str(error), file=sys.stderr)
        return 1
    finally:
        (reports / (args.suite + '-summary.json')).write_text(json.dumps(summary, indent=2) + '\n')
    return 0


if __name__ == '__main__':
    sys.exit(main())
