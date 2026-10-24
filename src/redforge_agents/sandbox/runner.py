"""Hardened sandbox for running a target agent and its mock tools.

Threat model: the agent under test and its (mocked) tools are UNTRUSTED. They run
in a Docker container with dropped capabilities, a non-root user, a read-only
root filesystem, and resource limits. Network is OFF by default; when the agent
needs to reach its instrumented mock tools, it is attached to a dedicated
internal bridge (`network="rfa-internal"`) that reaches only those mock services
— never the public internet. So an attack that tries to exfiltrate to a real
host simply cannot connect, and the attempt is still recorded as evidence.

Implementation uses the `docker` CLI via subprocess so the exact flags are
auditable. Output is read as UTF-8 with replacement (portable across hosts).
"""

from __future__ import annotations

import subprocess
from dataclasses import dataclass
from pathlib import Path

from redforge_agents.config import settings
from redforge_agents.logging_conf import get_logger

log = get_logger("sandbox")


@dataclass
class SandboxResult:
    exit_code: int
    stdout: str
    stderr: str
    timed_out: bool

    @property
    def ok(self) -> bool:
        return self.exit_code == 0 and not self.timed_out


class SandboxRunner:
    def __init__(
        self,
        image: str | None = None,
        memory: str | None = None,
        cpus: float | None = None,
        timeout_s: int | None = None,
        network: str = "none",  # "none" or an internal bridge name for mock services
    ) -> None:
        self.image = image or settings.sandbox_image
        self.memory = memory or settings.sandbox_memory
        self.cpus = cpus or settings.sandbox_cpus
        self.timeout_s = timeout_s or settings.sandbox_timeout_s
        self.network = network

    def _flags(self, workspace: Path) -> list[str]:
        return [
            "docker", "run", "--rm",
            f"--network={self.network}",
            f"--memory={self.memory}",
            f"--cpus={self.cpus}",
            "--pids-limit=256",
            "--cap-drop=ALL",
            "--security-opt=no-new-privileges",
            "--user=1000:1000",
            "--read-only",
            "--tmpfs=/tmp:size=128m",
            "-v", f"{workspace.resolve()}:/work:rw",
            "-w", "/work",
            self.image,
        ]

    def run(self, command: str, workspace: Path) -> SandboxResult:
        workspace.mkdir(parents=True, exist_ok=True)
        argv = self._flags(workspace) + ["bash", "-lc", command]
        log.info("sandbox exec (network=%s): %s", self.network, command)
        try:
            proc = subprocess.run(
                argv, capture_output=True, text=True, encoding="utf-8",
                errors="replace", timeout=self.timeout_s, check=False,
            )
            return SandboxResult(proc.returncode, proc.stdout, proc.stderr, False)
        except subprocess.TimeoutExpired as exc:
            log.warning("sandbox timed out after %ss", self.timeout_s)
            out = exc.stdout if isinstance(exc.stdout, str) else (exc.stdout or b"").decode("utf-8", "replace")
            err = exc.stderr if isinstance(exc.stderr, str) else (exc.stderr or b"").decode("utf-8", "replace")
            return SandboxResult(124, out, err, True)
