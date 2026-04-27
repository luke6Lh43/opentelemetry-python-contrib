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

API
---
"""

from __future__ import annotations

from typing import Any, Collection

from asyncua.client.client import Client
from asyncua.client.ua_client import UaClient
from asyncua.common.node import Node
from wrapt import wrap_function_wrapper

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


def _record_exception(span, exc: BaseException) -> None:
    """Attach exception info to a span per OTel conventions."""
    if not span.is_recording():
        return
    span.set_status(Status(StatusCode.ERROR, str(exc)))
    span.record_exception(exc)
    span.set_attribute(_ERROR_TYPE, type(exc).__qualname__)


# ----- Wrapper factories -----


def _wrap_connect(tracer: Tracer):
    async def wrapper(wrapped, instance, args, kwargs):
        with tracer.start_as_current_span(
            "opcua.connect",
            kind=SpanKind.CLIENT,
        ) as span:
            if span.is_recording():
                span.set_attribute(_OPCUA_OPERATION, "connect")
                endpoint = _safe_endpoint(instance)
                host = _safe_host(instance)
                port = _safe_port(instance)
                if endpoint:
                    span.set_attribute(_OPCUA_ENDPOINT, endpoint)
                if host:
                    span.set_attribute(_SERVER_ADDRESS, host)
                if port is not None:
                    span.set_attribute(_SERVER_PORT, port)
                security_policy = _safe_security_policy(instance)
                if security_policy:
                    span.set_attribute(_OPCUA_SECURITY_POLICY, security_policy)
                security_mode = _safe_security_mode(instance)
                if security_mode:
                    span.set_attribute(_OPCUA_SECURITY_MODE, security_mode)
            try:
                return await wrapped(*args, **kwargs)
            except Exception as exc:
                _record_exception(span, exc)
                raise

    return wrapper


def _wrap_disconnect(tracer: Tracer):
    async def wrapper(wrapped, instance, args, kwargs):
        with tracer.start_as_current_span(
            "opcua.disconnect",
            kind=SpanKind.CLIENT,
        ) as span:
            if span.is_recording():
                span.set_attribute(_OPCUA_OPERATION, "disconnect")
                endpoint = _safe_endpoint(instance)
                if endpoint:
                    span.set_attribute(_OPCUA_ENDPOINT, endpoint)
            try:
                return await wrapped(*args, **kwargs)
            except Exception as exc:
                _record_exception(span, exc)
                raise

    return wrapper


def _wrap_read_value(tracer: Tracer):
    async def wrapper(wrapped, instance, args, kwargs):
        # Server-internal operations use the same Node class; skip those.
        if not _is_client_node(instance):
            return await wrapped(*args, **kwargs)

        with tracer.start_as_current_span(
            "opcua.read",
            kind=SpanKind.CLIENT,
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
