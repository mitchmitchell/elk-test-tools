"""JSON Schemas for the envelope and for each implemented command's ``data`` (§2, §4.1).

CI validates every command's output against these, so schema drift breaks CI.
The envelope schema is also checked in as ``schemas/envelope.schema.json``
(§11 item 5) so Tester can validate outside the tool.
"""

from __future__ import annotations

from typing import Any

from .envelope import SCHEMA_VERSION, CheckStatus, ErrorCode, Result, Severity

DIALECT = "https://json-schema.org/draft/2020-12/schema"
CHECK_ID_PATTERN = r"^[a-z0-9_]+(\.[a-z0-9_]+){2,}$"
UTC_PATTERN = r"^\d{4}-\d\d-\d\dT\d\d:\d\d:\d\dZ$"

_CHECK: dict[str, Any] = {
    "type": "object",
    "additionalProperties": False,
    "required": ["id", "status", "detail", "evidence", "duration_s"],
    "properties": {
        "id": {"type": "string", "pattern": CHECK_ID_PATTERN},
        "status": {"enum": [s.value for s in CheckStatus]},
        "detail": {"type": "string"},
        "evidence": {"type": "object"},
        "duration_s": {"type": "number", "minimum": 0},
    },
}

_ERROR: dict[str, Any] = {
    "type": "object",
    "additionalProperties": False,
    "required": ["code", "severity", "message", "hint", "check_id"],
    "properties": {
        "code": {"enum": [c.value for c in ErrorCode]},
        "severity": {"enum": [s.value for s in Severity]},
        "message": {"type": "string", "minLength": 1},
        "hint": {"type": "string"},
        "check_id": {"type": ["string", "null"]},
    },
}

_TARGET: dict[str, Any] = {
    "type": ["object", "null"],
    "additionalProperties": False,
    "properties": {
        "ha_url": {"type": "string"},
        "panel_mac": {"type": "string", "pattern": "^[0-9a-f]{12}$"},
        "panel_name_ok": {"type": "boolean"},
        "hacs_ref": {"type": "string"},
        "link": {"const": "own"},
    },
}


def envelope_schema() -> dict[str, Any]:
    return {
        "$schema": DIALECT,
        "$id": f"elk-verify/envelope/v{SCHEMA_VERSION}",
        "title": "elk-verify run envelope",
        "type": "object",
        "additionalProperties": False,
        "required": [
            "schema_version",
            "tool",
            "command",
            "argv_redacted",
            "target",
            "dry_run",
            "result",
            "started_at",
            "finished_at",
            "duration_s",
            "checks",
            "data",
            "planned",
            "errors",
            "cleanup",
        ],
        "properties": {
            "schema_version": {"const": SCHEMA_VERSION},
            "tool": {
                "type": "object",
                "additionalProperties": False,
                "required": ["name", "version", "elke27_version"],
                "properties": {
                    "name": {"const": "elk-verify"},
                    "version": {"type": "string", "minLength": 1},
                    "elke27_version": {"type": ["string", "null"]},
                },
            },
            "command": {"type": ["string", "null"]},
            "argv_redacted": {"type": "array", "items": {"type": "string"}},
            "target": _TARGET,
            "dry_run": {"type": "boolean"},
            "result": {"enum": [r.value for r in Result]},
            "started_at": {"type": "string", "pattern": UTC_PATTERN},
            "finished_at": {"type": "string", "pattern": UTC_PATTERN},
            "duration_s": {"type": "number", "minimum": 0},
            "checks": {"type": "array", "items": _CHECK},
            "data": {"type": "object"},
            "planned": {"type": "array", "items": {"type": "object"}},
            "errors": {"type": "array", "items": _ERROR},
            "cleanup": {"type": ["string", "null"]},
        },
    }


def _data(title: str, properties: dict[str, Any]) -> dict[str, Any]:
    return {
        "$schema": DIALECT,
        "title": title,
        "type": "object",
        "additionalProperties": False,
        "required": sorted(properties),
        "properties": properties,
    }


def data_schemas() -> dict[str, dict[str, Any]]:
    """``data`` schema per implemented command. Networked commands are added as built."""
    return {
        "version": _data(
            "elk-verify version data",
            {
                "tool_version": {"type": "string"},
                "elke27_version": {"type": ["string", "null"]},
                "schema_version": {"const": SCHEMA_VERSION},
            },
        ),
        "schema": _data(
            "elk-verify schema data",
            {
                "name": {"type": "string"},
                "schema": {"type": "object"},
            },
        ),
    }


def schema_names() -> list[str]:
    return ["envelope", *sorted(data_schemas())]


def get_schema(name: str) -> dict[str, Any] | None:
    if name == "envelope":
        return envelope_schema()
    return data_schemas().get(name)
