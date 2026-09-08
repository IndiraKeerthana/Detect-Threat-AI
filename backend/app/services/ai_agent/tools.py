"""Strict, read-only tools over normalized Step 5/6 evidence."""

from __future__ import annotations

import ipaddress
import json
import re
from dataclasses import dataclass
from typing import Any, Callable
from urllib.parse import urlsplit

DOMAIN_RE = re.compile(r"^(?=.{1,253}$)(?:[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?\.)+[a-zA-Z]{2,63}$")
TOOL_NAMES = (
    "get_entity_details",
    "inspect_ip",
    "inspect_domain",
    "inspect_url",
    "inspect_dns",
    "inspect_rdap",
    "inspect_reputation",
    "query_graph",
    "explain_indicator",
)


class ToolValidationError(ValueError):
    """The model requested an unregistered or unsupported operation."""


TOOL_SPECIFICATIONS: list[dict[str, Any]] = [
    {
        "type": "function",
        "function": {
            "name": "inspect_url",
            "description": "Inspect URL components (scheme, hostname, path, query) and matching security observations from evidence.",
            "parameters": {
                "type": "object",
                "properties": {
                    "url": {"type": "string", "description": "The normalized HTTP or HTTPS URL from evidence to inspect."}
                },
                "required": ["url"],
            },
        },
    },
    {
        "type": "function",
        "function": {
            "name": "inspect_domain",
            "description": "Inspect domain details, DNS records, registration, and security observations from evidence.",
            "parameters": {
                "type": "object",
                "properties": {
                    "domain": {"type": "string", "description": "The domain name from evidence to inspect."}
                },
                "required": ["domain"],
            },
        },
    },
    {
        "type": "function",
        "function": {
            "name": "inspect_ip",
            "description": "Inspect IP address reputation, abuse score, geolocation, and ASN observations from evidence.",
            "parameters": {
                "type": "object",
                "properties": {
                    "ip": {"type": "string", "description": "The IPv4 or IPv6 address from evidence to inspect."}
                },
                "required": ["ip"],
            },
        },
    },
    {
        "type": "function",
        "function": {
            "name": "inspect_dns",
            "description": "Inspect DNS records (A, MX, TXT) for a domain present in evidence.",
            "parameters": {
                "type": "object",
                "properties": {
                    "domain": {"type": "string", "description": "The domain name to retrieve DNS records for."}
                },
                "required": ["domain"],
            },
        },
    },
    {
        "type": "function",
        "function": {
            "name": "inspect_rdap",
            "description": "Inspect WHOIS / RDAP registration records (registrar, creation date, age) for a domain present in evidence.",
            "parameters": {
                "type": "object",
                "properties": {
                    "domain": {"type": "string", "description": "The domain name to query registration for."}
                },
                "required": ["domain"],
            },
        },
    },
    {
        "type": "function",
        "function": {
            "name": "inspect_reputation",
            "description": "Inspect threat intelligence reputation observations (AbuseIPDB, VirusTotal) for an IP or domain.",
            "parameters": {
                "type": "object",
                "properties": {
                    "entity_type": {"type": "string", "enum": ["ip", "domain"], "description": "Type of entity to inspect ('ip' or 'domain')."},
                    "entity": {"type": "string", "description": "The IP address or domain name to inspect reputation for."}
                },
                "required": ["entity_type", "entity"],
            },
        },
    },
    {
        "type": "function",
        "function": {
            "name": "query_graph",
            "description": "Query relationships, connected entities, and edges in the evidence graph. If entity is omitted, queries the entire graph.",
            "parameters": {
                "type": "object",
                "properties": {
                    "entity": {"type": "string", "description": "Optional entity value to filter connected graph nodes and edges."}
                },
            },
        },
    },
    {
        "type": "function",
        "function": {
            "name": "explain_indicator",
            "description": "Retrieve full explanation, severity, and evidence bindings for a specific security indicator code.",
            "parameters": {
                "type": "object",
                "properties": {
                    "code": {"type": "string", "description": "The security indicator code from evidence (e.g. 'spf_fail', 'content_credential_request')."}
                },
                "required": ["code"],
            },
        },
    },
    {
        "type": "function",
        "function": {
            "name": "get_entity_details",
            "description": "Inspect normalized entity record and all matching security observations for an entity present in evidence.",
            "parameters": {
                "type": "object",
                "properties": {
                    "entity_type": {"type": "string", "enum": ["ip", "domain", "url"], "description": "Type of the entity."},
                    "entity": {"type": "string", "description": "The observable value from evidence."}
                },
                "required": ["entity_type", "entity"],
            },
        },
    },
]


@dataclass
class ToolRegistry:
    context: dict[str, Any]

    @property
    def names(self) -> list[str]:
        return list(TOOL_NAMES)

    def get_tools_schema(self) -> list[dict[str, Any]]:
        """Return standard OpenAI-compatible function specifications for registered tools."""
        return [dict(spec) for spec in TOOL_SPECIFICATIONS if spec["function"]["name"] in TOOL_NAMES]

    def execute(self, name: str, arguments: dict[str, Any] | None = None) -> dict[str, Any]:
        if name not in TOOL_NAMES:
            raise ToolValidationError("tool is not registered")
        if not isinstance(arguments, dict):
            raise ToolValidationError("tool arguments must be an object")
        if any(key.lower() in {"shell", "command", "attachment", "secret", "download"} for key in arguments):
            raise ToolValidationError("unsupported tool argument")
        handler = getattr(self, f"_{name}")
        return handler(arguments)

    def _entities(self) -> list[dict[str, Any]]:
        return [item for item in self.context.get("entities", []) if isinstance(item, dict)]

    def _observations(self) -> list[dict[str, Any]]:
        return [item for item in self.context.get("observations", []) if isinstance(item, dict)]

    def _find(self, entity_type: str, value: str) -> dict[str, Any]:
        needle = value.strip().lower()
        for entity in self._entities():
            if str(entity.get("type", "")).lower() == entity_type.lower() and str(
                entity.get("value", "")
            ).lower() == needle:
                return entity
        raise ToolValidationError("entity is not present in evidence")

    @staticmethod
    def _required(args: dict[str, Any], *keys: str) -> tuple[str, ...]:
        if set(args) - set(keys):
            raise ToolValidationError("unexpected tool argument")
        values = tuple(args.get(key) for key in keys)
        if any(not isinstance(value, str) or not value.strip() for value in values):
            raise ToolValidationError("missing or invalid entity")
        return tuple(value.strip() for value in values)

    @staticmethod
    def _single(args: dict[str, Any], *aliases: str) -> str:
        if len(args) != 1 or next(iter(args), None) not in aliases:
            raise ToolValidationError("unexpected or missing tool argument")
        value = next(iter(args.values()))
        if not isinstance(value, str) or not value.strip():
            raise ToolValidationError("missing or invalid entity")
        return value.strip()

    def _get_entity_details(self, args: dict[str, Any]) -> dict[str, Any]:
        if "entity_type" not in args and "entity" in args:
            val = str(args["entity"]).strip()
            if "://" in val:
                entity_type = "url"
            else:
                try:
                    ipaddress.ip_address(val)
                    entity_type = "ip"
                except ValueError:
                    entity_type = "domain"
            value = val
        else:
            entity_type, value = self._required(args, "entity_type", "entity")
        entity = self._find(entity_type, value)
        observations = [
            item
            for item in self._observations()
            if item.get("entity_type") == entity_type and str(item.get("entity", "")).lower() == value.lower()
        ]
        return {"tool": "get_entity_details", "entity": entity, "observations": observations}

    def _inspect_ip(self, args: dict[str, Any]) -> dict[str, Any]:
        value = self._single(args, "entity", "ip")
        try:
            ipaddress.ip_address(value)
        except ValueError as exc:
            raise ToolValidationError("invalid IP address") from exc
        entity = self._find("ip", value)
        return self._observations_for("inspect_ip", "ip", entity["value"], entity)

    def _inspect_domain(self, args: dict[str, Any]) -> dict[str, Any]:
        value = self._single(args, "entity", "domain")
        if not DOMAIN_RE.fullmatch(value.lower()):
            raise ToolValidationError("invalid domain")
        entity = self._find("domain", value)
        return self._observations_for("inspect_domain", "domain", entity["value"], entity)

    def _inspect_url(self, args: dict[str, Any]) -> dict[str, Any]:
        value = self._single(args, "entity", "url")
        parsed = urlsplit(value)
        if parsed.scheme not in {"http", "https"} or not parsed.hostname:
            raise ToolValidationError("invalid URL")
        entity = self._find("url", value)
        # Parsing is deliberately the only URL operation; no request/download
        # is ever made by this tool.
        return {
            "tool": "inspect_url",
            "entity": entity,
            "url_metadata": {
                "scheme": parsed.scheme,
                "hostname": parsed.hostname.lower(),
                "path": parsed.path,
                "has_query": bool(parsed.query),
            },
            "observations": self._matching_observations("url", entity["value"]),
        }

    def _inspect_dns(self, args: dict[str, Any]) -> dict[str, Any]:
        value = self._single(args, "entity", "domain")
        entity = self._find("domain", value)
        return self._observations_for("inspect_dns", "domain", entity["value"], entity, kinds={"dns", "registration"})

    def _inspect_rdap(self, args: dict[str, Any]) -> dict[str, Any]:
        value = self._single(args, "entity", "domain")
        entity = self._find("domain", value)
        return self._observations_for("inspect_rdap", "domain", entity["value"], entity, kinds={"rdap", "registration"})

    def _inspect_reputation(self, args: dict[str, Any]) -> dict[str, Any]:
        if "entity_type" not in args:
            if "ip" in args:
                entity_type, value = "ip", str(args["ip"]).strip()
            elif "domain" in args:
                entity_type, value = "domain", str(args["domain"]).strip()
            elif "entity" in args:
                val = str(args["entity"]).strip()
                try:
                    ipaddress.ip_address(val)
                    entity_type = "ip"
                except ValueError:
                    entity_type = "domain"
                value = val
            else:
                entity_type, value = self._required(args, "entity_type", "entity")
        else:
            entity_type, value = self._required(args, "entity_type", "entity")
        entity = self._find(entity_type, value)
        return self._observations_for("inspect_reputation", entity_type, entity["value"], entity, kinds={"reputation"})

    def _query_graph(self, args: dict[str, Any]) -> dict[str, Any]:
        if set(args) - {"entity"}:
            raise ToolValidationError("unexpected tool argument")
        value = args.get("entity")
        if value is not None:
            if not isinstance(value, str) or not value.strip():
                raise ToolValidationError("invalid graph entity")
            if not any(str(item.get("value", "")).lower() == value.lower() for item in self._entities()):
                raise ToolValidationError("entity is not present in evidence")
            nodes = [item for item in self.context.get("graph", {}).get("nodes", []) if str(item.get("value", "")).lower() == value.lower()]
            edges = [
                item for item in self.context.get("graph", {}).get("edges", [])
                if str(item.get("source", "")).lower() == value.lower()
                or str(item.get("target", "")).lower() == value.lower()
            ]
        else:
            nodes = self.context.get("graph", {}).get("nodes", [])
            edges = self.context.get("graph", {}).get("edges", [])
        return {"tool": "query_graph", "nodes": nodes, "edges": edges}

    def _explain_indicator(self, args: dict[str, Any]) -> dict[str, Any]:
        code = self._single(args, "code", "indicator")
        indicators = self.context.get("indicators", [])
        matches = [item for item in indicators if str(item.get("code", "")).lower() == code.lower()]
        if not matches:
            raise ToolValidationError("indicator is not present in evidence")
        return {"tool": "explain_indicator", "indicators": matches}

    def _matching_observations(self, entity_type: str, entity: str) -> list[dict[str, Any]]:
        return [
            item for item in self._observations()
            if item.get("entity_type") == entity_type and str(item.get("entity", "")).lower() == entity.lower()
        ]

    def _observations_for(
        self,
        tool: str,
        entity_type: str,
        entity: str,
        entity_record: dict[str, Any],
        *,
        kinds: set[str] | None = None,
    ) -> dict[str, Any]:
        observations = self._matching_observations(entity_type, entity)
        if kinds is not None:
            observations = [item for item in observations if str(item.get("kind", "")).lower() in kinds]
        return {"tool": tool, "entity": entity_record, "observations": observations}


def tool_call_key(name: str, arguments: dict[str, Any]) -> str:
    """Canonical key used to prevent repeated provider calls."""
    return name + ":" + json.dumps(arguments, sort_keys=True, separators=(",", ":"))


def make_tool_registry(context: dict[str, Any]) -> ToolRegistry:
    return ToolRegistry(context=context)


# Public registry metadata is immutable; execution always requires a
# context-bound ToolRegistry instance.
TOOL_REGISTRY = frozenset(TOOL_NAMES)


def validate_tool_call(
    name: str, arguments: dict[str, Any], context: dict[str, Any]
) -> dict[str, Any]:
    """Validate and execute one call for integrations and focused tests."""
    return make_tool_registry(context).execute(name, arguments)
