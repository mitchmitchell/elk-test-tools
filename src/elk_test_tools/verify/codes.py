"""Panel codes from the environment (acceptance A11/A12, design §7). Offline, pure."""

from __future__ import annotations

from collections.abc import Mapping

from .envelope import HINTS, ErrorCode, ErrorItem, Severity


class CodeError(Exception):
    def __init__(self, item: ErrorItem) -> None:
        super().__init__(item.code.value)
        self.item = item


def load_code(env: Mapping[str, str], name: str) -> str:
    """Read a code from ``name``. Never from argv; never echoed in errors.

    Missing or empty → E_CODE_MISSING. Not all digits, a leading zero, or all
    zeros → E_CODE_INVALID (matches elke27 control_authenticate and HACS #94).
    """
    code = env.get(name)
    if not code:
        raise CodeError(
            ErrorItem(
                ErrorCode.E_CODE_MISSING,
                Severity.ABORT,
                f"{name} is not set — this command needs it",
                HINTS[ErrorCode.E_CODE_MISSING],
            )
        )
    if not (code.isascii() and code.isdigit()) or code.startswith("0"):
        raise CodeError(
            ErrorItem(
                ErrorCode.E_CODE_INVALID,
                Severity.ABORT,
                f"{name} is not a valid code — digits only, no leading zero, not all zeros",
                HINTS[ErrorCode.E_CODE_INVALID],
            )
        )
    return code
