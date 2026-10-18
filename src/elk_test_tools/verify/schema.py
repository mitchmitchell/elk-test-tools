"""JSON Schemas for the envelope and for each implemented command's ``data`` (§2, §4.1).

CI validates every command's output against these, so schema drift breaks CI.
The bundle of all of them is checked in as ``schemas/elk-verify.v1.json``
(§11 item 5, acceptance E5) so Tester can validate outside the tool.
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
                "name": {"type": "string", "minLength": 1},
                "schema": {"type": "object"},
            },
        ),
    }


# Stable check ids per command (§4.1, acceptance E4). Ids are listed only here
# and in `elk-verify schema`; renaming one is a schema-version change.
CHECK_IDS: dict[str, tuple[str, ...]] = {
    "version": ("tool.elke27.version", "tool.version.read"),
    "schema": ("schema.document.built",),
}

BUNDLE_ID = f"elk-verify.v{SCHEMA_VERSION}"


def _without_dialect(schema: dict[str, Any]) -> dict[str, Any]:
    return {k: v for k, v in schema.items() if k not in ("$schema", "$id")}


def command_schema(command: str) -> dict[str, Any] | None:
    """The full envelope schema for one command: its ids and its ``data``."""
    data = data_schemas().get(command)
    if data is None:
        return None
    env = envelope_schema()
    props = dict(env["properties"])
    props["command"] = {"const": command}
    check = dict(_CHECK)
    check["properties"] = dict(_CHECK["properties"]) | {"id": {"enum": list(CHECK_IDS[command])}}
    props["checks"] = {"type": "array", "items": check}
    props["data"] = _without_dialect(data)
    env["properties"] = props
    env["$id"] = f"elk-verify/{command}/v{SCHEMA_VERSION}"
    env["title"] = f"elk-verify {command} envelope"
    return env


def _aborted_schema() -> dict[str, Any]:
    """Any run refused before its command ran (usage, secret on argv, internal)."""
    env = envelope_schema()
    props = dict(env["properties"])
    props["result"] = {"const": "abort"}
    props["checks"] = {"type": "array", "maxItems": 0}
    props["data"] = {"type": "object", "maxProperties": 0}
    props["errors"] = {"type": "array", "items": _ERROR, "minItems": 1}
    env["properties"] = props
    return _without_dialect(env)


def bundle_schema() -> dict[str, Any]:
    """Every envelope the tool can print. Checked in as schemas/elk-verify.v1.json."""
    defs: dict[str, Any] = {"aborted": _aborted_schema()}
    for command in sorted(data_schemas()):
        cmd = command_schema(command)
        assert cmd is not None
        defs[f"command.{command}"] = _without_dialect(cmd)
    return {
        "$schema": DIALECT,
        "$id": BUNDLE_ID,
        "title": "elk-verify output (all commands)",
        "$defs": defs,
        "anyOf": [{"$ref": f"#/$defs/{name}"} for name in defs],
    }


def schema_names() -> list[str]:
    return sorted(data_schemas())


def get_schema(name: str | None) -> dict[str, Any] | None:
    """No name: the bundle. A command name: that command's envelope schema."""
    if name is None:
        return bundle_schema()
    return command_schema(name)
