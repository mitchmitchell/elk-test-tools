"""Exclusive lock shared by the link and remove commands.

``elk-link-test-tool`` and ``elk-remove-test-link`` take an exclusive, non-blocking
``flock`` on ``<link file>.lock`` (next to the link file) for their whole run. A
second concurrent run aborts before it touches the panel, so two runs can never
both provision a link (orphaning one) or race a removal. The lock file is never
deleted (unlinking would let a third run lock a different inode), holds no data,
and its path is never logged.
"""

from __future__ import annotations

import fcntl
import os
from collections.abc import Iterator
from contextlib import contextmanager
from pathlib import Path

from elk_test_tools.link_removal import AbortError

LOCK_SUFFIX = ".lock"


def lock_path_for(link_file: str | os.PathLike[str]) -> Path:
    path = Path(link_file)
    return path.parent / (path.name + LOCK_SUFFIX)


@contextmanager
def exclusive_link_lock(link_file: str | os.PathLike[str]) -> Iterator[None]:
    """Hold an exclusive lock next to ``link_file``; abort if another run has it."""
    lock = lock_path_for(link_file)
    try:
        fd = os.open(lock, os.O_RDWR | os.O_CREAT | os.O_NOFOLLOW, 0o600)
    except OSError:
        raise AbortError("cannot open the link lock file (link file directory)") from None
    try:
        try:
            fcntl.flock(fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
        except BlockingIOError:
            raise AbortError(
                "another elk-test-tools link/remove run is in progress; try again later"
            ) from None
        try:
            yield
        finally:
            fcntl.flock(fd, fcntl.LOCK_UN)
    finally:
        os.close(fd)
