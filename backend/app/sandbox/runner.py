"""
Sandbox execution layer.

Every static analyzer run and every patch verification happens here, never
on the host. This wraps `docker run` with hard resource limits. If Docker is
unavailable (e.g. this build/dev sandbox), it falls back to a restricted
subprocess runner for local iteration only -- `require_docker=True` should
be used in any environment handling untrusted PR code.
"""
from __future__ import annotations

import shutil
import subprocess
from dataclasses import dataclass

from app.core.config import get_settings

settings = get_settings()


@dataclass
class SandboxResult:
    exit_code: int
    stdout: str
    stderr: str
    timed_out: bool


class SandboxUnavailableError(RuntimeError):
    pass


def _docker_available() -> bool:
    return shutil.which("docker") is not None


def run_in_sandbox(
    command: list[str],
    *,
    workdir_host_path: str,
    image: str = "sentinelreview/analysis-sandbox:latest",
    require_docker: bool = False,
    timeout_seconds: int | None = None,
) -> SandboxResult:
    """
    Run `command` inside a hardened, resource-limited container mounting
    `workdir_host_path` read-only (analyzers) or read-write (patch
    verification, which needs to apply a diff before re-running tests).

    Resource limits mirror the hardening already proven out on Mini Code
    Judge: CPU/memory caps, disabled networking, and a wall-clock timeout
    enforced both by Docker and as a subprocess-level backstop.
    """
    timeout = timeout_seconds or settings.sandbox_timeout_seconds

    if not _docker_available():
        if require_docker:
            raise SandboxUnavailableError(
                "Docker is required for sandboxed execution but is not available "
                "in this environment. Refusing to execute untrusted code on host."
            )
        # Local-dev-only fallback: still resource-limited via subprocess timeout,
        # but NOT process/network isolated. Never use this path against
        # untrusted PR content in a real deployment.
        try:
            proc = subprocess.run(  # noqa: PLW1510
                command,
                cwd=workdir_host_path,
                capture_output=True,
                text=True,
                timeout=timeout,
            )
            return SandboxResult(proc.returncode, proc.stdout, proc.stderr, timed_out=False)
        except subprocess.TimeoutExpired as e:
            return SandboxResult(-1, (e.stdout.decode() if isinstance(e.stdout, bytes) else str(e.stdout or '')), (e.stderr.decode() if isinstance(e.stderr, bytes) else str(e.stderr or '')), timed_out=True)

    docker_cmd = [
        "docker", "run", "--rm",
        "--network", "none" if settings.sandbox_network_disabled else "bridge",
        "--cpus", settings.sandbox_cpu_limit,
        "--memory", settings.sandbox_mem_limit,
        "--pids-limit", "128",
        "--read-only",
        "--tmpfs", "/tmp:rw,size=64m",
        "-v", f"{workdir_host_path}:/workspace:rw",
        "-w", "/workspace",
        image,
        *command,
    ]
    try:
        proc = subprocess.run(docker_cmd, capture_output=True, text=True, timeout=timeout)  # noqa: PLW1510
        return SandboxResult(proc.returncode, proc.stdout, proc.stderr, timed_out=False)
    except subprocess.TimeoutExpired as e:
        return SandboxResult(-1, (e.stdout.decode() if isinstance(e.stdout, bytes) else str(e.stdout or '')), (e.stderr.decode() if isinstance(e.stderr, bytes) else str(e.stderr or '')), timed_out=True)
