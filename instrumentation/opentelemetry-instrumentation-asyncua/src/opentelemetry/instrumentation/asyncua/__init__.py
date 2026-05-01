"""
OpenTelemetry Instrumentation for asyncua (OPC UA)
---------------------------------------------------
Provides auto-instrumentation for the `asyncua` Python library, emitting
distributed traces for OPC UA client operations including:

- Unified client workflow root span (opcua.client) parenting discovery +
  session into a single trace
- Session lifecycle (connect/disconnect) with grouped child spans
- Endpoint discovery (connect_and_get_server_endpoints + get_endpoints)
  with per-endpoint span events
- Handshake decomposition (open_secure_channel, create_session,
  activate_session)
- Node operations (read, write, call_method)
- Security posture capture (policies, modes, certificate fingerprints,
  transport profiles, server application identity)

Verified against: asyncua==1.1.8, Python 3.12
"""

from __future__ import annotations

import hashlib
import logging
import threading
import time
from contextlib import contextmanager
from typing import Any, Callable, Collection, Iterable

import wrapt
from opentelemetry import trace
from opentelemetry.context import attach, detach
from opentelemetry.instrumentation.asyncua.package import _instruments
from opentelemetry.instrumentation.asyncua.version import __version__
from opentelemetry.instrumentation.instrumentor import BaseInstrumentor
from opentelemetry.instrumentation.utils import unwrap
from opentelemetry.trace import SpanKind, Status, StatusCode

logger = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------

_MAX_ENDPOINT_EVENTS = 25
_WORKFLOW_IDLE_TTL_SEC = 30.0
_HASH_PREFIX_LENGTH = 16

# ---------------------------------------------------------------------------
# Workflow registry
# ---------------------------------------------------------------------------
# A "workflow" is the unified client-scoped trace. It is keyed by server URL
# so that a standalone pre-connect discovery call (which has no Client
# instance context) can share the same parent trace as the subsequent
# Client.connect() / operations / disconnect().
#
# Lifecycle:
#   - Created lazily on the first instrumented call for a URL
#     (either connect_and_get_server_endpoints OR Client.connect)
#   - Torn down on Client.disconnect() for any client bound to that URL
#   - Idle workflows (discovery-only, no connect within TTL) are reaped
#     to prevent leaks when a user calls only discovery and never connects.

_WORKFLOWS: dict[str, dict[str, Any]] = {}
_WORKFLOWS_LOCK = threading.Lock()
_CLIENT_TO_URL: dict[int, str] = {}
_SESSION_SPANS: dict[int, trace.Span] = {}
_SESSION_TOKENS: dict[int, Any] = {}


def _get_tracer() -> trace.Tracer:
    return trace.get_tracer(__name__, __version__)


def _normalize_url(url: str | None) -> str:
    if not url:
        return ""
    return str(url).strip().rstrip("/").lower()


def _reap_stale_workflows() -> None:
    """End any discovery-only workflows that were never followed by connect()."""
    now = time.monotonic()
    with _WORKFLOWS_LOCK:
        stale_keys = [
            key for key, entry in _WORKFLOWS.items()
            if not entry["bound_client_ids"]
            and not entry["has_session"]
            and (now - entry["created_at"]) > _WORKFLOW_IDLE_TTL_SEC
        ]
        for key in stale_keys:
            entry = _WORKFLOWS.pop(key, None)
            if entry:
                _safe_detach(entry["context_token"])
                _safe_end_span(entry["span"])
                logger.debug("Reaped stale workflow for %s", key)


def _get_or_create_workflow(url: str, reason: str) -> dict[str, Any]:
    """Return the workflow entry for a URL, creating it if needed."""
    _reap_stale_workflows()
    key = _normalize_url(url)
    with _WORKFLOWS_LOCK:
        entry = _WORKFLOWS.get(key)
        if entry is not None:
            return entry

        span = _get_tracer().start_span(
            "opcua.client",
            kind=SpanKind.CLIENT,
            attributes={
                "opcua.server.url": str(url) if url else "",
                "opcua.client.workflow.initiated_by": reason,
            },
        )
        token = attach(trace.set_span_in_context(span))

        entry = {
            "span": span,
            "context_token": token,
            "bound_client_ids": set(),
            "created_at": time.monotonic(),
            "has_session": False,
        }
        _WORKFLOWS[key] = entry
        logger.debug("Workflow created for %s (reason=%s)", key, reason)
        return entry


def _bind_client_to_workflow(instance: Any, url: str) -> dict[str, Any] | None:
    key = _normalize_url(url)
    with _WORKFLOWS_LOCK:
        entry = _WORKFLOWS.get(key)
        if entry is None:
            return None
        entry["bound_client_ids"].add(id(instance))
        entry["has_session"] = True
        _CLIENT_TO_URL[id(instance)] = key
        return entry


def _release_client_from_workflow(instance: Any) -> None:
    """Release a client; end the workflow span when the last client detaches."""
    key = _CLIENT_TO_URL.pop(id(instance), None)
    if key is None:
        return
    with _WORKFLOWS_LOCK:
        entry = _WORKFLOWS.get(key)
        if entry is None:
            return
        entry["bound_client_ids"].discard(id(instance))
        if not entry["bound_client_ids"]:
            _WORKFLOWS.pop(key, None)
            _safe_detach(entry["context_token"])
            _safe_end_span(entry["span"])
            logger.debug("Workflow ended for %s (last client disconnected)", key)


# ---------------------------------------------------------------------------
# Safe utility helpers
# ---------------------------------------------------------------------------

def _safe_detach(token: Any) -> None:
    try:
        detach(token)
    except Exception:  # pragma: no cover
        pass


def _safe_end_span(span: trace.Span) -> None:
    try:
        span.end()
    except Exception:  # pragma: no cover
        pass


def _hash_prefix(data: bytes | None) -> str | None:
    """Return a short SHA-256 prefix (hex) for privacy-safe identification."""
    if not data:
        return None
    try:
        return hashlib.sha256(bytes(data)).hexdigest()[:_HASH_PREFIX_LENGTH]
    except Exception:
        return None


@contextmanager
def _traced_span(name: str, attrs: dict[str, Any] | None = None):
    """Context manager that starts a span, handles errors, and sets status."""
    tracer = _get_tracer()
    with tracer.start_as_current_span(name, kind=SpanKind.CLIENT) as span:
        if attrs:
            for k, v in attrs.items():
                span.set_attribute(k, v)
        try:
            yield span
        except Exception as exc:
            span.set_status(Status(StatusCode.ERROR, str(exc)))
            span.record_exception(exc)
            raise


# ---------------------------------------------------------------------------
# Attribute extraction
# ---------------------------------------------------------------------------

def _extract_security_attrs(instance: Any) -> dict[str, Any]:
    """Extract security-related attributes from an asyncua Client instance."""
    attrs: dict[str, Any] = {}

    sec_policy = getattr(instance, "security_policy", None)
    if sec_policy is not None:
        uri = getattr(sec_policy, "URI", None)
        if uri:
            attrs["opcua.security.policy_uri"] = uri
            attrs["opcua.security.policy"] = uri.rsplit("#", 1)[-1]

        mode = getattr(sec_policy, "Mode", None)
        mode_name = getattr(mode, "name", None)
        if mode_name:
            attrs["opcua.security.mode"] = mode_name

        fp = _hash_prefix(getattr(sec_policy, "peer_certificate", None))
        if fp:
            attrs["opcua.security.server_cert.sha256_prefix"] = fp

    uaclient = getattr(instance, "uaclient", None)
    if uaclient is not None:
        auth_token = (
            getattr(uaclient, "_session_authentication_token", None)
            or getattr(uaclient, "authentication_token", None)
        )
        token_identifier = getattr(auth_token, "Identifier", None) if auth_token else None
        token_hash = _hash_prefix(token_identifier)
        if token_hash:
            attrs["opcua.session.auth_token.sha256_prefix"] = token_hash

    return attrs


def _node_attrs(node: Any) -> dict[str, Any]:
    """Extract attributes from a Node's NodeId."""
    attrs: dict[str, Any] = {}
    try:
        nodeid = getattr(node, "nodeid", None)
        if nodeid is None:
            return attrs
        attrs["opcua.node_id"] = nodeid.to_string()
        attrs["opcua.node_id.namespace_index"] = int(getattr(nodeid, "NamespaceIndex", 0))
        attrs["opcua.node_id.identifier"] = str(getattr(nodeid, "Identifier", ""))
        nodeid_type = getattr(nodeid, "NodeIdType", None)
        attrs["opcua.node_id.type"] = getattr(nodeid_type, "name", str(nodeid_type))
    except Exception:
        pass
    return attrs


def _is_client_node(node: Any) -> bool:
    """Filter out server-side Node objects to keep traces clean."""
    try:
        from asyncua.client.ua_client import UaClient
        return isinstance(getattr(node, "session", None), UaClient)
    except Exception:
        return False


# ---------------------------------------------------------------------------
# Endpoint enumeration helpers
# ---------------------------------------------------------------------------

def _policy_short_name(policy_uri: str) -> str:
    return policy_uri.rsplit("#", 1)[-1] if "#" in policy_uri else policy_uri


def _enum_name(value: Any, default: str = "Unknown") -> str:
    return getattr(value, "name", str(value) if value is not None else default)


def _extract_server_identity(server_desc: Any) -> dict[str, str]:
    """Extract ApplicationDescription fields from an endpoint's Server field."""
    if server_desc is None:
        return {"application_uri": "", "application_name": "", "application_type": "", "product_uri": ""}

    app_name_obj = getattr(server_desc, "ApplicationName", None)
    app_type_obj = getattr(server_desc, "ApplicationType", None)
    return {
        "application_uri": getattr(server_desc, "ApplicationUri", "") or "",
        "product_uri": getattr(server_desc, "ProductUri", "") or "",
        "application_name": str(getattr(app_name_obj, "Text", "") or "") if app_name_obj else "",
        "application_type": _enum_name(app_type_obj, default=""),
    }


def _summarize_endpoints(endpoint_list: Iterable[Any]) -> dict[str, Any]:
    """Compute aggregate attributes across all endpoints."""
    policies: set[str] = set()
    modes: set[str] = set()
    token_types: set[str] = set()
    transport_profiles: set[str] = set()
    server_app_uris: set[str] = set()
    insecure_count = 0
    max_security_level = 0

    for ep in endpoint_list:
        policy_short = _policy_short_name(getattr(ep, "SecurityPolicyUri", "") or "")
        policies.add(policy_short or "Unknown")

        mode_name = _enum_name(getattr(ep, "SecurityMode", None))
        modes.add(mode_name)

        if policy_short in ("None", "") and mode_name in ("None_", "None"):
            insecure_count += 1

        for utp in getattr(ep, "UserIdentityTokens", []) or []:
            token_types.add(_enum_name(getattr(utp, "TokenType", None)))

        try:
            sec_level_int = int(getattr(ep, "SecurityLevel", 0) or 0)
            max_security_level = max(max_security_level, sec_level_int)
        except (TypeError, ValueError):
            pass

        transport = getattr(ep, "TransportProfileUri", "") or ""
        if transport:
            transport_profiles.add(transport.rsplit("/", 1)[-1])

        app_uri = _extract_server_identity(getattr(ep, "Server", None))["application_uri"]
        if app_uri:
            server_app_uris.add(app_uri)

    return {
        "opcua.endpoints.security_policies": sorted(policies),
        "opcua.endpoints.security_modes": sorted(modes),
        "opcua.endpoints.user_token_types": sorted(token_types),
        "opcua.endpoints.insecure_count": insecure_count,
        "opcua.endpoints.max_security_level": max_security_level,
        "opcua.endpoints.transport_profiles": sorted(transport_profiles),
        "opcua.endpoints.server_application_uris": sorted(server_app_uris),
    }


def _endpoint_event_attrs(ep: Any, idx: int) -> dict[str, Any]:
    """Build span-event attributes describing a single endpoint."""
    policy_short = _policy_short_name(getattr(ep, "SecurityPolicyUri", "") or "")
    mode_name = _enum_name(getattr(ep, "SecurityMode", None))
    transport = getattr(ep, "TransportProfileUri", "") or ""
    security_level = getattr(ep, "SecurityLevel", 0) or 0
    identity = _extract_server_identity(getattr(ep, "Server", None))

    try:
        security_level_int = int(security_level)
    except (TypeError, ValueError):
        security_level_int = 0

    return {
        "index": idx,
        "endpoint_url": getattr(ep, "EndpointUrl", "") or "",
        "security_policy": policy_short or "Unknown",
        "security_mode": mode_name,
        "security_level": security_level_int,
        "server_cert.sha256_prefix": _hash_prefix(getattr(ep, "ServerCertificate", None)) or "none",
        "transport_profile": transport.rsplit("/", 1)[-1] if transport else "",
        **identity,
    }


def _annotate_endpoints_span(span: trace.Span, endpoints: Iterable[Any]) -> None:
    """Attach aggregate attributes and per-endpoint events to a span."""
    endpoint_list = list(endpoints) if endpoints else []
    span.set_attribute("opcua.endpoints.count", len(endpoint_list))

    for k, v in _summarize_endpoints(endpoint_list).items():
        span.set_attribute(k, v)

    for idx, ep in enumerate(endpoint_list[:_MAX_ENDPOINT_EVENTS]):
        span.add_event("opcua.endpoint", attributes=_endpoint_event_attrs(ep, idx))

    truncated = len(endpoint_list) - _MAX_ENDPOINT_EVENTS
    if truncated > 0:
        span.set_attribute("opcua.endpoints.truncated", True)
        span.set_attribute("opcua.endpoints.truncated_count", truncated)


# ---------------------------------------------------------------------------
# Wrapper factories
# ---------------------------------------------------------------------------

def _make_security_annotated_wrapper(span_name: str) -> Callable:
    """Factory for handshake sub-operations that annotate security attrs on success."""
    async def _wrapper(wrapped, instance, args, kwargs):
        with _traced_span(span_name) as span:
            result = await wrapped(*args, **kwargs)
            for k, v in _extract_security_attrs(instance).items():
                span.set_attribute(k, v)
            return result
    return _wrapper


def _make_node_wrapper(
    span_name: str,
    capture_value_type: bool = False,
    extra_attrs_fn: Callable[[tuple, dict], dict[str, Any]] | None = None,
) -> Callable:
    """Factory for Node-level operations (read/write/call_method)."""
    async def _wrapper(wrapped, instance, args, kwargs):
        if not _is_client_node(instance):
            return await wrapped(*args, **kwargs)

        base_attrs = _node_attrs(instance)
        if extra_attrs_fn:
            base_attrs.update(extra_attrs_fn(args, kwargs))

        with _traced_span(span_name, attrs=base_attrs) as span:
            result = await wrapped(*args, **kwargs)
            if capture_value_type:
                span.set_attribute("opcua.value.type", type(result).__name__)
            return result
    return _wrapper


def _write_extra_attrs(args: tuple, kwargs: dict) -> dict[str, Any]:
    return {"opcua.value.type": type(args[0]).__name__} if args else {}


def _call_method_extra_attrs(args: tuple, kwargs: dict) -> dict[str, Any]:
    return {"opcua.method.name": str(args[0])} if args else {}


# ---------------------------------------------------------------------------
# Client lifecycle wrappers
# ---------------------------------------------------------------------------

async def _traced_connect(wrapped, instance, args, kwargs):
    tracer = _get_tracer()
    server_url = str(getattr(instance, "server_url", ""))

    workflow = _get_or_create_workflow(server_url, reason="connect")
    _bind_client_to_workflow(instance, server_url)

    # Session span is parented by the workflow span
    workflow_ctx = trace.set_span_in_context(workflow["span"])
    session_span = tracer.start_span(
        "opcua.session",
        kind=SpanKind.CLIENT,
        context=workflow_ctx,
        attributes={"opcua.server.url": server_url},
    )
    session_token = attach(trace.set_span_in_context(session_span))
    _SESSION_SPANS[id(instance)] = session_span
    _SESSION_TOKENS[id(instance)] = session_token

    with tracer.start_as_current_span("opcua.connect", kind=SpanKind.CLIENT) as span:
        try:
            result = await wrapped(*args, **kwargs)
            for k, v in _extract_security_attrs(instance).items():
                span.set_attribute(k, v)
                session_span.set_attribute(k, v)
            return result
        except Exception as exc:
            span.set_status(Status(StatusCode.ERROR, str(exc)))
            span.record_exception(exc)
            session_span.set_status(Status(StatusCode.ERROR, str(exc)))
            raise


async def _traced_disconnect(wrapped, instance, args, kwargs):
    try:
        with _traced_span("opcua.disconnect"):
            return await wrapped(*args, **kwargs)
    finally:
        session_span = _SESSION_SPANS.pop(id(instance), None)
        session_token = _SESSION_TOKENS.pop(id(instance), None)
        if session_token is not None:
            _safe_detach(session_token)
        if session_span is not None:
            _safe_end_span(session_span)
        _release_client_from_workflow(instance)


# ---------------------------------------------------------------------------
# Endpoint discovery wrappers
# ---------------------------------------------------------------------------

async def _traced_connect_and_get_server_endpoints(wrapped, instance, args, kwargs):
    """Pre-connect discovery — parented by the unified workflow span."""
    server_url = str(getattr(instance, "server_url", ""))
    workflow = _get_or_create_workflow(server_url, reason="discovery")
    workflow_ctx = trace.set_span_in_context(workflow["span"])
    ctx_token = attach(workflow_ctx)

    try:
        with _traced_span(
            "opcua.discover_endpoints",
            attrs={"opcua.server.url": server_url},
        ):
            return await wrapped(*args, **kwargs)
    finally:
        _safe_detach(ctx_token)


async def _traced_get_endpoints(wrapped, instance, args, kwargs):
    server_url = str(getattr(instance, "server_url", ""))
    with _traced_span("opcua.get_endpoints", attrs={"opcua.server.url": server_url}) as span:
        endpoints = await wrapped(*args, **kwargs)
        try:
            _annotate_endpoints_span(span, endpoints)
        except Exception as enum_exc:  # never break the real call on annotation failure
            logger.debug("Endpoint enumeration failed: %s", enum_exc)
            span.set_attribute("opcua.endpoints.enumeration_error", str(enum_exc))
        return endpoints


# ---------------------------------------------------------------------------
# Generated wrappers
# ---------------------------------------------------------------------------

_traced_open_secure_channel = _make_security_annotated_wrapper("opcua.open_secure_channel")
_traced_create_session      = _make_security_annotated_wrapper("opcua.create_session")
_traced_activate_session    = _make_security_annotated_wrapper("opcua.activate_session")

_traced_read_value  = _make_node_wrapper("opcua.read", capture_value_type=True)
_traced_write_value = _make_node_wrapper("opcua.write", extra_attrs_fn=_write_extra_attrs)
_traced_call_method = _make_node_wrapper("opcua.call_method", extra_attrs_fn=_call_method_extra_attrs)


# ---------------------------------------------------------------------------
# Instrumentor
# ---------------------------------------------------------------------------

# Targets: (module_path, class_attr, wrapper)
_WRAP_TARGETS: list[tuple[str, str, Callable]] = [
    ("asyncua.client.client", "Client.connect", _traced_connect),
    ("asyncua.client.client", "Client.disconnect", _traced_disconnect),
    ("asyncua.client.client", "Client.get_endpoints", _traced_get_endpoints),
    ("asyncua.client.client", "Client.connect_and_get_server_endpoints",
     _traced_connect_and_get_server_endpoints),
    ("asyncua.client.client", "Client.open_secure_channel", _traced_open_secure_channel),
    ("asyncua.client.client", "Client.create_session", _traced_create_session),
    ("asyncua.client.client", "Client.activate_session", _traced_activate_session),
    ("asyncua.common.node", "Node.read_value", _traced_read_value),
    ("asyncua.common.node", "Node.write_value", _traced_write_value),
    ("asyncua.common.node", "Node.call_method", _traced_call_method),
]


class AsyncuaInstrumentor(BaseInstrumentor):
    """OpenTelemetry instrumentor for the asyncua OPC UA client library."""

    def instrumentation_dependencies(self) -> Collection[str]:
        return _instruments

    def _instrument(self, **kwargs):
        for module, attr, wrapper in _WRAP_TARGETS:
            wrapt.wrap_function_wrapper(module, attr, wrapper)

    def _uninstrument(self, **kwargs):
        import asyncua.client.client as client_mod
        import asyncua.common.node as node_mod

        module_map = {
            "asyncua.client.client": client_mod.Client,
            "asyncua.common.node": node_mod.Node,
        }

        for module, attr, _ in _WRAP_TARGETS:
            _, method_name = attr.split(".", 1)
            cls = module_map.get(module)
            if cls is not None:
                try:
                    unwrap(cls, method_name)
                except Exception as exc:  # pragma: no cover
                    logger.debug("unwrap failed for %s.%s: %s", module, attr, exc)

        # Flush workflow / session state
        with _WORKFLOWS_LOCK:
            for entry in _WORKFLOWS.values():
                _safe_detach(entry["context_token"])
                _safe_end_span(entry["span"])
            _WORKFLOWS.clear()
        _CLIENT_TO_URL.clear()
        _SESSION_SPANS.clear()
        _SESSION_TOKENS.clear()