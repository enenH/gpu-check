"""Real ZUI overlay lifecycle regression. Root is only a host evidence-export fallback.

The test APK creates/removes an app-owned window; the production detector receives no title or PID.
No settings or app permissions are changed. Run after building ServiceDeviceInstrumentation.
"""
import argparse
import gzip
import hashlib
import json
import pathlib
import shlex
import subprocess
import sys
import time

parser = argparse.ArgumentParser()
parser.add_argument('--serial', required=True)
parser.add_argument('--seconds', type=int, default=110)
parser.add_argument('--output', default='build/overlay-lenovo-device-test/fixture')
parser.add_argument('--verify-only', action='store_true', help='Recover evidence from the completed App run without rerunning it')
args = parser.parse_args()
root = pathlib.Path(__file__).resolve().parents[1]
out = root / args.output
out.mkdir(parents=True, exist_ok=True)


def adb(*command, timeout=30):
    # Avoid the wireless bridge's unreliable shell-v2 status/PTY framing for read-only exports.
    if command[0] == 'shell':
        remote = command[1] if len(command) == 2 else ' '.join(shlex.quote(arg) for arg in command[1:])
        command = ('exec-out', 'sh -c ' + shlex.quote(remote))
    attempts = 3 if command[0] in ('shell', 'exec-out') else 1
    for attempt in range(attempts):
        try:
            return subprocess.check_output(['adb', '-s', args.serial, *command], timeout=timeout)
        except (subprocess.CalledProcessError, subprocess.TimeoutExpired):
            if attempt + 1 == attempts:
                raise
            print('Retrying read-only ADB evidence command', file=sys.stderr, flush=True)
            time.sleep(1)


def snapshot(stage):
    data = adb('shell', 'dumpsys', 'SurfaceFlinger')
    assert b'Layer [' in data, 'Independent SurfaceFlinger dump did not contain layer records'
    (out / (stage + '-surfaceflinger.txt')).write_bytes(data)
    (out / (stage + '-processes.txt')).write_bytes(adb('shell', 'ps', '-A', '-o', 'USER,PID,NAME'))


def export(name, compressed=False):
    # run-as is disabled on the connected ZUI firmware. This command only exports app-written files.
    path = '/data/user/0/com.gpucheck.app/files/' + name
    command = ('gzip -c ' if compressed else 'cat ') + shlex.quote(path)
    destination = out / (name + '.gz' if compressed else name)
    with destination.open('wb') as stream:
        subprocess.run(['adb', '-s', args.serial, 'exec-out', 'su -c ' + shlex.quote(command)],
                       stdout=stream, check=True, timeout=60)
    return destination


if not args.verify_only:
    print(adb('install', '-r', str(root / 'app/build/outputs/apk/debug/app-debug.apk')).decode(), flush=True)
    print(adb('install', '-r', str(root / 'app/build/outputs/apk/androidTest/debug/app-debug-androidTest.apk')).decode(), flush=True)
    snapshot('before')
    command = ['adb', '-s', args.serial, 'shell', 'am', 'instrument', '-w', '-r', '-e', 'duration_seconds',
               str(args.seconds), '-e', 'overlay_fixture', 'true',
               'com.gpucheck.app.test/com.gpucheck.app.ServiceDeviceInstrumentation']
    process = subprocess.Popen(command, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, encoding='utf8', errors='replace')
    with (out / 'instrumentation.txt').open('w', encoding='utf8') as log:
        for line in process.stdout:
            log.write(line)
            log.flush()
            print(line.rstrip(), flush=True)
            if 'stage=OVERLAY_FIXTURE_CREATED' in line:
                snapshot('fixture-created')
            elif 'stage=OVERLAY_FIXTURE_DETECTED' in line:
                snapshot('fixture-detected')
            elif 'stage=OVERLAY_FIXTURE_DISAPPEARED' in line:
                snapshot('fixture-disappeared')
    if process.wait() != 0:
        raise RuntimeError('Instrumentation command failed')
elif not (out / 'fixture-disappeared-surfaceflinger.txt').exists():
    snapshot('fixture-disappeared')
    (out / 'recovered-export.txt').write_text('Independent disappearance snapshot recovered after App completion; original host dump command returned 255. App-written result is validated separately.\n', encoding='utf8')

summary = json.loads(export('service-device-summary.json').read_text(encoding='utf8'))
export('service-real.jsonl', True)
export('service-ui.jsonl', True)
for name in ['service-ui-active.png', 'service-ui-stopped.png', 'service-ui-background.png',
             'overlay-details.png', 'overlay-fixture-hit.png', 'overlay-fixture.json']:
    if summary.get('result') == 'PASS' or name != 'overlay-fixture-hit.png':
        export(name)
assert summary['result'] == 'PASS', summary.get('error')
assert not summary['validationIssues'], summary['validationIssues']
assert summary['overlayFixtureLifecyclePassed']
assert summary['appUid'] >= 10000 and int(summary['appCapEff'], 16) == 0
assert summary['appSelinux'].startswith('u:r:untrusted_app')
fixture = summary['overlayFixture']
name = fixture['name']
assert fixture['absentFromFreshCollection'] and not fixture['targetNameSuppliedToDetector']
assert fixture['firstHit']['route'] == 'zui' and fixture['firstHit']['suspicious']
assert fixture['firstHit']['ownerPid'] == summary['appPid'] and fixture['firstHit']['ownerUid'] == summary['appUid']
assert name in fixture['hitUi']['overlayNames']
assert fixture['hitUi']['overlayStatus'] == '外挂悬浮窗'
assert fixture['hitUi']['overlayColor'] == -34947
assert name in (out / 'fixture-detected-surfaceflinger.txt').read_text(encoding='utf8', errors='replace')
assert name not in (out / 'fixture-disappeared-surfaceflinger.txt').read_text(encoding='utf8', errors='replace')
states, collections = {}, {}
with gzip.open(out / 'service-real.jsonl.gz', 'rt', encoding='utf8') as stream, (out / 'overlay-only.jsonl').open('w', encoding='utf8') as target:
    for line in stream:
        report = json.loads(line)
        overlay = report['overlay']
        assert not overlay['brandGateUsed'] and len(overlay['routes']) == 3
        target.write(json.dumps({'sampleIndex': report['sampleIndex'], 'collectorUid': report['collectorUid'],
                                 'overlay': overlay}, ensure_ascii=False) + '\n')
        for route in overlay['routes']:
            assert route['appUid'] == summary['appUid']
            states[route['route']] = route['status']
            if route['route'] == 'zui' and route['available']:
                assert route['temporaryFilesRemoved']
                collections[route['observedAtMs']] = {'rows': len(route['rows']), 'durationMs': route['durationMs']}
assert len(collections) >= 2
assert summary['buttonStop']['reportCleared'] and summary['backgroundStop']['reportCleared']
apk_path = adb('shell', 'pm', 'path', 'com.gpucheck.app').decode().strip().removeprefix('package:')
installed = adb('exec-out', 'cat', apk_path)
local = (root / 'app/build/outputs/apk/debug/app-debug.apk').read_bytes()
assert hashlib.sha256(installed).digest() == hashlib.sha256(local).digest()
(out / 'installed.apk').write_bytes(installed)
(out / 'package.txt').write_bytes(adb('shell', 'dumpsys', 'package', 'com.gpucheck.app'))
(out / 'external-directory-after.txt').write_bytes(adb('shell', "su -c 'find /data/media/0/Android/data/com.gpucheck.app/files -maxdepth 1 -name sys_gpucheck_* -print'"))
assert not (out / 'external-directory-after.txt').read_text().strip(), 'Temporary ZUI directories remain'
result = {'result': 'PASS', 'serial': args.serial, 'appVersion': summary['installedVersion'],
          'appUid': summary['appUid'], 'appSelinux': summary['appSelinux'], 'appCapEff': summary['appCapEff'],
          'realSamples': summary['realSamples'], 'fixture': fixture, 'collections': collections,
          'lastRouteStates': states, 'apkSha256': hashlib.sha256(local).hexdigest(), 'installedApkMatches': True,
          'temporaryZuiDirectoriesRemoved': True, 'ordinaryAppDetection': True,
          'hostRootUsedOnlyForEvidenceExport': True, 'realCheatProcessClaimed': False,
          'evidenceExportRecovered': args.verify_only,
          'stopRestartBackgroundPassed': True, 'syntheticProtocolChecks': summary['overlayProtocolRegression']['checks']}
(out / 'verification.json').write_text(json.dumps(result, ensure_ascii=False, indent=2), encoding='utf8')
print(json.dumps({key: value for key, value in result.items() if key != 'fixture'}, ensure_ascii=False, indent=2), flush=True)
