#!/usr/bin/env python3
"""Container health check (Dockerfile HEALTHCHECK): GET /health/live on the local gunicorn.

Web mode: gunicorn always binds 0.0.0.0:8000 (tools/docker-entrypoint.sh), so the port is
fixed on purpose; a PORT env set by a platform does not move gunicorn. /health/live answers
in LivenessMiddleware, before SecurityMiddleware, sessions and the database, so it needs no
auth, does no DB or Redis work and is never redirected to https. The Host and
X-Forwarded-Proto headers keep it passing even if that middleware order changes.

Worker mode (entrypoint `worker`): there is no HTTP server. The entrypoint writes
``/tmp/identity-worker-mode`` and supervises the Celery worker and beat. If either
exits, the entrypoint stops the other and the container exits, so Docker restarts it.
The check passes when that marker is present.

Output never includes env values; only the error class is printed.
"""

import os
import sys
import urllib.request

WORKER_MODE_MARKER = '/tmp/identity-worker-mode'


def _is_worker_mode() -> bool:
    """True when this container is running the worker entrypoint (no gunicorn)."""
    if os.path.exists(WORKER_MODE_MARKER):
        return True
    # Images before 0.13.3 exec'd Celery as PID 1 in worker mode.
    try:
        with open('/proc/1/cmdline', 'rb') as fh:
            argv = fh.read().decode('utf-8', 'replace').split('\0')
    except OSError:
        return False
    return any(os.path.basename(arg) == 'celery' for arg in argv[:3])


def main() -> int:
    if _is_worker_mode():
        return 0
    hosts = [h.strip() for h in os.getenv('ALLOWED_HOSTS', '').split(',') if h.strip()]
    host = next((h.lstrip('.') for h in hosts if h != '*'), 'localhost')
    request = urllib.request.Request(
        'http://127.0.0.1:8000/health/live',
        headers={'Host': host, 'X-Forwarded-Proto': 'https'},
    )
    try:
        with urllib.request.urlopen(request, timeout=4) as response:
            return 0 if response.status == 200 else 1
    except Exception as exc:  # noqa: BLE001
        print(f'healthcheck failed: {type(exc).__name__}', file=sys.stderr)
        return 1


if __name__ == '__main__':
    sys.exit(main())
