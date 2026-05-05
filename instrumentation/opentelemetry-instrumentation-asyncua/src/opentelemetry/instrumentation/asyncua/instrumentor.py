import wrapt
from asyncua.common.node import Node

from opentelemetry import trace
from opentelemetry.instrumentation.asyncua.package import _instruments
from opentelemetry.instrumentation.instrumentor import BaseInstrumentor
from opentelemetry.instrumentation.utils import unwrap


async def _read_value_wrapper(wrapped, instance, args, kwargs):
    tracer = trace.get_tracer(__name__)
    with tracer.start_as_current_span("opcua.read"):
        return await wrapped(*args, **kwargs)


class AsyncUAInstrumentor(BaseInstrumentor):
    def instrumentation_dependencies(self):
        return _instruments

    def _instrument(self, **kwargs):
        wrapt.wrap_function_wrapper(
            "asyncua.common.node",
            "Node.read_value",
            _read_value_wrapper,
        )

    def _uninstrument(self, **kwargs):
        unwrap(Node, "read_value")
