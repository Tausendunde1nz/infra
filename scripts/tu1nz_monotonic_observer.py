"""Read-only health observations; monotonic minimums, no policy writes."""
import argparse, hashlib, importlib.util, json, pathlib, time

SECOND = 1_000_000_000
MINIMUMS = (0, 30, 60, 90)
TARGETS = (0, 31, 61, 95)

def monotonic_ns():
    # Python3.9 macOS time.monotonic_ns has a process-local epoch.
    # Native CLOCK_MONOTONIC is monotonic and shared across processes.
    return time.clock_gettime_ns(time.CLOCK_MONOTONIC)

def valid_observation(observation, activation, transaction, now_ns):
    try:
        start = activation['observation_start_ns']
        end = observation['completed_monotonic_ns']
        samples = observation['samples']
        if type(start) is not int or type(end) is not int:
            return False
        if observation['transaction'] != transaction or observation['candidate_sha256'] != activation['sha256']:
            return False
        if observation['observation_start_ns'] != start or observation.get('complete') is not True:
            return False
        if end - start < 90 * SECOND or now_ns < end or len(samples) != 4:
            return False
        previous_end = start
        for index, (sample, minimum) in enumerate(zip(samples, MINIMUMS)):
            begin, finish = sample['started_monotonic_ns'], sample['finished_monotonic_ns']
            if type(begin) is not int or type(finish) is not int:
                return False
            if sample['minimum_seconds'] != minimum or sample['passed'] is not True:
                return False
            if begin < previous_end or begin - start < minimum * SECOND or finish < begin or finish > end:
                return False
            if index == 0 and begin - start > 20 * SECOND:
                return False
            if len(sample['evidence_sha256']) != 64:
                return False
            previous_end = finish
        return True
    except (KeyError, TypeError, ValueError):
        return False

def observe(directory, baseline_path):
    # Late import avoids a module cycle with the watchdog validator.
    import tu1nz_policy_watchdog as w
    w.protect()
    directory = pathlib.Path(directory)
    manifest = json.loads(w.read_private(directory / 'manifest.json'))
    activation = json.loads(w.read_private(directory / 'ACTIVATED.json'))
    baseline = json.loads(w.read_private(pathlib.Path(baseline_path)))
    assert not (directory / 'ROLLED_BACK.json').exists()
    spec = importlib.util.spec_from_file_location('health', '/Users/daniel/.codex/tu1nz-recovery/phase5-20260924T162425Z/phase5-check.py')
    health = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(health)
    result = {'transaction': manifest['transaction'], 'candidate_sha256': activation['sha256'],
              'observation_start_ns': activation['observation_start_ns'], 'samples': [], 'complete': False}
    try:
        for minimum, target in zip(MINIMUMS, TARGETS):
            due = activation['observation_start_ns'] + target * SECOND
            while True:
                remaining = due - monotonic_ns()
                if remaining <= 0:
                    break
                time.sleep(min(remaining / SECOND, 1))
            assert not (directory / 'ROLLED_BACK.json').exists()
            begin = monotonic_ns()
            if minimum == 0:
                assert begin - activation['observation_start_ns'] <= 20 * SECOND
            data = health.collect()
            for key in ['containers', 'firewall', 'listeners', 'services']:
                assert data['server'][key] == baseline['server'][key], key + ' changed'
            finish = monotonic_ns()
            evidence = directory / ('observation-%02d.json' % minimum)
            w.write_new(evidence, data)
            result['samples'].append({'minimum_seconds': minimum, 'started_monotonic_ns': begin,
                'finished_monotonic_ns': finish, 'passed': True,
                'evidence_sha256': w.sha(evidence.read_bytes())})
            print('MONOTONIC_HEALTH_PASS', minimum, round((finish - activation['observation_start_ns']) / SECOND, 3), flush=True)
        result['completed_monotonic_ns'] = monotonic_ns()
        result['complete'] = True
        assert valid_observation(result, activation, manifest['transaction'], monotonic_ns())
        w.write_new(directory / 'OBSERVATION.json', result)
    except BaseException as error:
        result['complete'] = False
        result['failure_kind'] = type(error).__name__
        w.write_new(directory / 'OBSERVATION_FAILED.json', result)
        if not (directory / 'ROLLBACK_NOW').exists():
            w.write_new(directory / 'ROLLBACK_NOW', b'Monotonic observation failed or interrupted.\n')
        raise

if __name__ == '__main__':
    parser = argparse.ArgumentParser()
    parser.add_argument('--directory', required=True)
    parser.add_argument('--baseline', required=True)
    args = parser.parse_args()
    try:
        observe(args.directory, args.baseline)
    except BaseException:
        print('OBSERVATION_STOP: rollback requested; no completion evidence.', flush=True)
        raise SystemExit(1)
