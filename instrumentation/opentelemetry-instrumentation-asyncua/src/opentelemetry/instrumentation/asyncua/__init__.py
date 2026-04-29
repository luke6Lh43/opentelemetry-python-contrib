# Copyright The OpenTelemetry Authors
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.

"""
This library allows tracing OPC UA client operations made by the
`asyncua <https://github.com/FreeOpcUa/opcua-asyncio>`_ library.

Usage
-----

Run instrumented code:

.. code-block:: python

    import asyncio
    from asyncua import Client
    from opentelemetry.instrumentation.asyncua import AsyncuaInstrumentor

    AsyncuaInstrumentor().instrument()

    async def main():
        async with Client(url="opc.tcp://localhost:4840/freeopcua/server/") as client:
            node = client.get_node("i=85")
            value = await node.read_value()
            print(value)

    asyncio.run(main())

Only client-initiated operations are traced. The instrumentor installs
wrappers on the shared ``Node`` class (which is also used by asyncua's
server internals); server-side bookkeeping operations are filtered out
by inspecting the node's session type.

Session-level grouping
----------------------

For each connected ``Client``, the instrumentor opens a long-lived
``opcua.session`` span on ``Client.connect()`` and closes it on
``Client.disconnect()``. All intermediate read / write / call_method
spans become children of this session span, so a full client session
appears as a single trace with a coherent parent-child structure.

If an enclosing span is already active when ``connect()`` runs (for
example, an HTTP request span from an outer framework), the
``opcua.session`` span will naturally parent to it, preserving the
full distributed trace across process boundaries.

API
---
"""

from __future__ import annotations

from typing import Any, Collection

from asyncua.client.client import Client
from asyncua.client.ua_client import UaClient
from asyncua.common.node import Node
from wrapt import wrap_function_wrapper

from opentelemetry import context as otel_context
from opentelemetry import trace
from opentelemetry.instrumentation.asyncua.package import _instruments
from opentelemetry.instrumentation.asyncua.version import __version__
from opentelemetry.instrumentation.instrumentor import BaseInstrumentor
from opentelemetry.instrumentation.utils import unwrap
from opentelemetry.trace import SpanKind, Tracer
from opentelemetry.trace.status import Status, StatusCode

# Attribute namespace used by this instrumentation for OPC UA-specific fields.
# Note: No stable OpenTelemetry semantic conventions for OPC UA exist yet.
# These attributes are provisional and may change to align with future stable
# conventions in opentelemetry/semantic-conventions.
_OPCUA_OPERATION = "opcua.operation"
_OPCUA_ENDPOINT = "opcua.endpoint"
_OPCUA_NODE_ID = "opcua.node_id"
_OPCUA_METHOD_ID = "opcua.method_id"
_OPCUA_METHOD_ARGS_COUNT = "opcua.method_args_count"
_OPCUA_VARIANT_TYPE = "opcua.variant_type"
_OPCUA_SECURITY_POLICY = "opcua.security_policy"
_OPCUA_SECURITY_MODE = "opcua.security_mode"

# Standard OTel attributes.
_SERVER_ADDRESS = "server.address"
_SERVER_PORT = "server.port"
_ERROR_TYPE = "error.type"

# Per-Client state stashed by _wrap_connect and consumed by _wrap_disconnect.
# Stored as an attribute on the Client instance (value: tuple[Span, Token]).
# A dunder-like private name avoids collision with asyncua's own fields and
# any user subclassing.
_SESSION_STATE_ATTR = "_otel_asyncua_session_state"


class AsyncuaInstrumentor(BaseInstrumentor):
    """An instrumentor for the asyncua OPC UA client library.

    See `BaseInstrumentor`.
    """

    def instrumentation_dependencies(self) -> Collection[str]:
        return _instruments

    def _instrument(self, **kwargs: Any) -> None:
        tracer_provider = kwargs.get("tracer_provider")
        tracer = trace.get_tracer(
            __name__,
            __version__,
            tracer_provider,
        )

        # Client lifecycle (asyncua/client/client.py)
        wrap_function_wrapper(
            "asyncua.client.client",
            "Client.connect",
            _wrap_connect(tracer),
        )
        wrap_function_wrapper(
            "asyncua.client.client",
            "Client.disconnect",
            _wrap_disconnect(tracer),
        )

        # Node operations (asyncua/common/node.py). The Node class is shared
        # between client and server code paths; wrappers filter server-side
        # use via _is_client_node().
        wrap_function_wrapper(
            "asyncua.common.node",
            "Node.read_value",
            _wrap_read_value(tracer),
        )
        wrap_function_wrapper(
            "asyncua.common.node",
            "Node.write_value",
            _wrap_write_value(tracer),
        )
        wrap_function_wrapper(
            "asyncua.common.node",
            "Node.call_method",
            _wrap_call_method(tracer),
        )

    def _uninstrument(self, **kwargs: Any) -> None:
        unwrap(Client, "connect")
        unwrap(Client, "disconnect")
        unwrap(Node, "read_value")
        unwrap(Node, "write_value")
        unwrap(Node, "call_method")


# ----- Helpers -----


def _is_client_node(node: Any) -> bool:
    """Return True if the Node is associated with a client-side session.

    asyncua's ``Node`` class is used by both client and server code. This
    instrumentation targets client-side operations only; server-internal
    reads/writes (e.g. during address space setup) should pass through
    without generating spans.
    """
    try:
        return isinstance(node.session, UaClient)
    except Exception:  # pylint: disable=broad-except
        return False


def _safe_node_id(node: Any) -> str | None:
    """Return a human-readable string representation of a Node's id.

    Prefers the OPC UA canonical ``to_string`` form when available
    (e.g. ``ns=2;i=42``) and falls back to ``str(nodeid)``.
    """
    try:
        node_id = node.nodeid
        if hasattr(node_id, "to_string"):
            return node_id.to_string()
        return str(node_id)
    except Exception:  # pylint: disable=broad-except
        return None


def _safe_endpoint(client: Any) -> str | None:
    try:
        return client.server_url.geturl()
    except Exception:  # pylint: disable=broad-except
        return None


def _safe_host(client: Any) -> str | None:
    try:
        return client.server_url.hostname
    except Exception:  # pylint: disable=broad-except
        return None


def _safe_port(client: Any) -> int | None:
    try:
        return client.server_url.port
    except Exception:  # pylint: disable=broad-except
        return None


def _safe_security_policy(client: Any) -> str | None:
    """Return the security policy short name (e.g. 'None', 'Basic256Sha256').

    asyncua's Client.security_policy is an instance of a SecurityPolicy
    subclass whose ``URI`` attribute holds the full policy URI, e.g.
    ``http://opcfoundation.org/UA/SecurityPolicy#Basic256Sha256``. We
    return the short name after the ``#``.
    """
    try:
        policy = getattr(client, "security_policy", None)
        if policy is None:
            return None
        uri = getattr(policy, "URI", None)
        if isinstance(uri, str) and "#" in uri:
            return uri.rsplit("#", 1)[-1]
        return None
    except Exception:  # pylint: disable=broad-except
        return None


def _safe_security_mode(client: Any) -> str | None:
    """Return the security mode name ('None', 'Sign', 'SignAndEncrypt').

    asyncua stores the security mode on the security policy object as
    ``policy.Mode``, an instance of ``ua.MessageSecurityMode``. The
    ``None_`` enum name is normalized to ``None`` for readability.
    """
    try:
        policy = getattr(client, "security_policy", None)
        if policy is None:
            return None
        mode = getattr(policy, "Mode", None)
        if mode is None:
            return None
        name = getattr(mode, "name", None)
        if name == "None_":
            return "None"
        return name if name else str(mode)
    except Exception:  # pylint: disable=broad-except
        return None


def _set_connection_attributes(span, client: Any) -> None:
    """Attach endpoint / host / port attributes to a span.

    Used by both the session span and the connect span so connection
    context is visible regardless of which span a viewer focuses on.
    """
    if not span.is_recording():
        return
    endpoint = _safe_endpoint(client)
    host = _safe_host(client)
    port = _safe_port(client)
    if endpoint:
        span.set_attribute(_OPCUA_ENDPOINT, endpoint)
    if host:
        span.set_attribute(_SERVER_ADDRESS, host)
    if port is not None:
        span.set_attribute(_SERVER_PORT, port)


def _set_security_attributes(span, client: Any) -> None:
    """Attach security policy / mode attributes to a span.

    These are only reliably populated after a successful connect; calling
    this helper before ``connect()`` returns is safe (missing values are
    simply skipped).
    """
    if not span.is_recording():
        return
    security_policy = _safe_security_policy(client)
    if security_policy:
        span.set_attribute(_OPCUA_SECURITY_POLICY, security_policy)
    security_mode = _safe_security_mode(client)
    if security_mode:
        span.set_attribute(_OPCUA_SECURITY_MODE, security_mode)


def _record_exception(span, exc: BaseException) -> None:
    """Attach exception info to a span per OTel conventions.

    Wrappers pair this with ``record_exception=False`` on
    ``start_as_current_span`` so the context manager doesn't also
    auto-record the same exception (which would produce duplicate
    exception events on the span).
    """
    if not span.is_recording():
        return
    span.set_status(Status(StatusCode.ERROR, str(exc)))
    span.record_exception(exc)
    span.set_attribute(_ERROR_TYPE, type(exc).__qualname__)


def _end_session(instance: Any, exc: BaseException | None = None) -> None:
    """Close out a session span previously attached to ``instance``.

    Safe to call multiple times; a no-op if no session is currently
    attached to the Client. If an exception is supplied, it is recorded
    on the session span before it is closed.
    """
    state = getattr(instance, _SESSION_STATE_ATTR, None)
    if state is None:
        return
    session_span, token = state
    try:
        if exc is not None:
            _record_exception(session_span, exc)
        session_span.end()
    finally:
        otel_context.detach(token)
        try:
            delattr(instance, _SESSION_STATE_ATTR)
        except AttributeError:
            pass


# ----- Wrapper factories -----


def _wrap_connect(tracer: Tracer):
    """Wrap Client.connect() to open a session-level span.

    The session span lives from ``connect()`` until the matching
    ``disconnect()`` (or until connect itself fails). Because it spans
    multiple awaits, it is started as a *detached* span and attached to
    the current context manually — not via a ``with`` block.

    Inside connect(), a short-lived ``opcua.connect`` child span is
    opened so the connect phase remains visible as its own operation.
    """
    async def wrapper(wrapped, instance, args, kwargs):
        # If a previous session wasn't cleaned up (e.g. connect() called
        # twice without disconnect()), close it first to avoid leaking
        # spans or stacking contexts.
        if getattr(instance, _SESSION_STATE_ATTR, None) is not None:
            _end_session(instance)

        # 1. Open the session span and attach it to the current context
        #    so that every child span emitted before disconnect() parents
        #    to it and shares its trace_id.
        session_span = tracer.start_span(
            "opcua.session",
            kind=SpanKind.CLIENT,
        )
        if session_span.is_recording():
            session_span.set_attribute(_OPCUA_OPERATION, "session")
            _set_connection_attributes(session_span, instance)

        ctx = trace.set_span_in_context(session_span)
        token = otel_context.attach(ctx)
        setattr(instance, _SESSION_STATE_ATTR, (session_span, token))

        # 2. Inside the session, record connect() itself as a child span.
        with tracer.start_as_current_span(
            "opcua.connect",
            kind=SpanKind.CLIENT,
            record_exception=False,
        ) as span:
            if span.is_recording():
                span.set_attribute(_OPCUA_OPERATION, "connect")
                _set_connection_attributes(span, instance)
                # Security details are typically not meaningful until
                # after the secure channel opens, but we try opportunistically.
                _set_security_attributes(span, instance)
            try:
                result = await wrapped(*args, **kwargs)
            except Exception as exc:
                _record_exception(span, exc)
                # The session never fully opened — close it now so we
                # don't leak a long-lived span on a failed connect.
                _end_session(instance, exc)
                raise

            # Post-connect: security attributes are now reliable. Copy
            # them onto the session span so the full-session view carries
            # the negotiated policy/mode even if the connect span is
            # collapsed in the UI.
            _set_security_attributes(span, instance)
            state = getattr(instance, _SESSION_STATE_ATTR, None)
            if state is not None:
                _set_security_attributes(state[0], instance)
            return result

    return wrapper


def _wrap_disconnect(tracer: Tracer):
    """Wrap Client.disconnect() to close out the session span.

    The ``opcua.disconnect`` span itself is a child of the session span,
    giving a clean bookend to the trace.
    """
    async def wrapper(wrapped, instance, args, kwargs):
        with tracer.start_as_current_span(
            "opcua.disconnect",
            kind=SpanKind.CLIENT,
            record_exception=False,
        ) as span:
            if span.is_recording():
                span.set_attribute(_OPCUA_OPERATION, "disconnect")
                endpoint = _safe_endpoint(instance)
                if endpoint:
                    span.set_attribute(_OPCUA_ENDPOINT, endpoint)
            try:
                result = await wrapped(*args, **kwargs)
            except Exception as exc:
                _record_exception(span, exc)
                # Still end the session — disconnect failing doesn't
                # justify leaking the session span forever.
                _end_session(instance, exc)
                raise

            _end_session(instance)
            return result

    return wrapper


def _wrap_read_value(tracer: Tracer):
    async def wrapper(wrapped, instance, args, kwargs):
        # Server-internal operations use the same Node class; skip those.
        if not _is_client_node(instance):
            return await wrapped(*args, **kwargs)

        with tracer.start_as_current_span(
            "opcua.read",
            kind=SpanKind.CLIENT,
            record_exception=False,
        ) as span:
            if span.is_recording():
                span.set_attribute(_OPCUA_OPERATION, "read")
                node_id = _safe_node_id(instance)
                if node_id:
                    span.set_attribute(_OPCUA_NODE_ID, node_id)
            try:
                return await wrapped(*args, **kwargs)
            except Exception as exc:
                _record_exception(span, exc)
                raise

    return wrapper


def _wrap_write_value(tracer: Tracer):
    async def wrapper(wrapped, instance, args, kwargs):
        if not _is_client_node(instance):
            return await wrapped(*args, **kwargs)

        with tracer.start_as_current_span(
            "opcua.write",
            kind=SpanKind.CLIENT,
            record_exception=False,
        ) as span:
            if span.is_recording():
                span.set_attribute(_OPCUA_OPERATION, "write")
                node_id = _safe_node_id(instance)
                if node_id:
                    span.set_attribute(_OPCUA_NODE_ID, node_id)
                # Signature: write_value(value, varianttype=None).
                # We do NOT capture the value itself (could be sensitive
                # or large). Variant type is safe metadata.
                variant_type = kwargs.get("varianttype")
                if variant_type is None and len(args) >= 2:
                    variant_type = args[1]
                if variant_type is not None:
                    span.set_attribute(_OPCUA_VARIANT_TYPE, str(variant_type))
            try:
                return await wrapped(*args, **kwargs)
            except Exception as exc:
                _record_exception(span, exc)
                raise

    return wrapper


def _wrap_call_method(tracer: Tracer):
    async def wrapper(wrapped, instance, args, kwargs):
        if not _is_client_node(instance):
            return await wrapped(*args, **kwargs)

        with tracer.start_as_current_span(
            "opcua.call_method",
            kind=SpanKind.CLIENT,
            record_exception=False,
        ) as span:
            if span.is_recording():
                span.set_attribute(_OPCUA_OPERATION, "call_method")
                parent_node_id = _safe_node_id(instance)
                if parent_node_id:
                    span.set_attribute(_OPCUA_NODE_ID, parent_node_id)
                # Signature: call_method(methodid, *args)
                if len(args) >= 1:
                    span.set_attribute(_OPCUA_METHOD_ID, str(args[0]))
                span.set_attribute(
                    _OPCUA_METHOD_ARGS_COUNT, max(0, len(args) - 1)
                )
            try:
                return await wrapped(*args, **kwargs)
            except Exception as exc:
                _record_exception(span, exc)
                raise

    return wrapper