"""Sandbox helpers.

Active tooling should run in an ephemeral, locked-down container. This module
builds the `docker run` command line with sane limits; it does not require Docker
to be installed just to import. The host is never handed raw agent-generated
commands: only a fixed tool + args inside a constrained container.
"""
import shutil
from typing import List, Optional


def docker_available() -> bool:
    return shutil.which("docker") is not None


def build_docker_cmd(image: str,
                     argv: List[str],
                     workspace: str,
                     network: str = "none",
                     memory: str = "512m",
                     cpus: str = "1.0",
                     pids_limit: int = 256,
                     read_only_root: bool = True) -> List[str]:
    """Return a `docker run` argv that runs `argv` inside `image`.

    Defaults are conservative: no network, read-only root fs, capped memory/cpu/
    pids, non-root user, the per-engagement workspace mounted read-write at /work.
    Pass network="bridge" only when the step genuinely needs egress.
    """
    cmd = [
        "docker", "run", "--rm",
        "--network", network,
        "--memory", memory,
        "--cpus", cpus,
        "--pids-limit", str(pids_limit),
        "--cap-drop", "ALL",
        "--security-opt", "no-new-privileges",
        "--user", "1000:1000",
        "-v", "%s:/work:rw" % workspace,
        "-w", "/work",
    ]
    if read_only_root:
        cmd += ["--read-only", "--tmpfs", "/tmp:rw,size=64m"]
    cmd.append(image)
    cmd += argv
    return cmd
