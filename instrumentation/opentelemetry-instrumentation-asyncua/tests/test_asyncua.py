import asyncio
from unittest.mock import patch

from asyncua.common.node import Node
from wrapt import ObjectProxy

from opentelemetry.instrumentation.asyncua import AsyncUAInstrumentor
from opentelemetry.test.test_base import TestBase


async def _fake_read_value(self):
    return 42


class TestAsyncUAInstrumentation(TestBase):
    def setUp(self):
        super().setUp()
        self.instrumentor = AsyncUAInstrumentor()

    def tearDown(self):
        super().tearDown()
        try:
            self.instrumentor.uninstrument()
        except Exception:
            pass

    def test_read_value_creates_span(self):
        with patch.object(Node, "read_value", _fake_read_value):
            self.instrumentor.instrument()
            node = Node.__new__(Node)
            result = asyncio.run(node.read_value())

        self.assertEqual(result, 42)
        spans = self.memory_exporter.get_finished_spans()
        self.assertEqual(len(spans), 1)
        self.assertEqual(spans[0].name, "opcua.read")

    def test_uninstrument_removes_wrapping(self):
        self.instrumentor.instrument()
        self.instrumentor.uninstrument()
        self.assertNotIsInstance(Node.read_value, ObjectProxy)

    def test_instrument_without_calls_produces_no_spans(self):
        self.instrumentor.instrument()
        spans = self.memory_exporter.get_finished_spans()
        self.assertEqual(len(spans), 0)
