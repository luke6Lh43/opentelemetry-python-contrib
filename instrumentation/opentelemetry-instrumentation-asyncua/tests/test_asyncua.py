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

from unittest import TestCase

from asyncua.client.client import Client
from asyncua.common.node import Node

from opentelemetry.instrumentation.asyncua import AsyncuaInstrumentor


class TestAsyncuaInstrumentor(TestCase):
    def test_instrument_and_uninstrument_cycle(self) -> None:
        """Instrument/uninstrument applies and removes method wrapping."""
        instrumentor = AsyncuaInstrumentor()
        self.assertFalse(hasattr(Client.connect, "__wrapped__"))
        self.assertFalse(hasattr(Node.read_value, "__wrapped__"))

        instrumentor.instrument()
        try:
            self.assertTrue(hasattr(Client.connect, "__wrapped__"))
            self.assertTrue(hasattr(Client.disconnect, "__wrapped__"))
            self.assertTrue(hasattr(Node.read_value, "__wrapped__"))
            self.assertTrue(hasattr(Node.write_value, "__wrapped__"))
            self.assertTrue(hasattr(Node.call_method, "__wrapped__"))
        finally:
            instrumentor.uninstrument()

        self.assertFalse(hasattr(Client.connect, "__wrapped__"))
        self.assertFalse(hasattr(Node.read_value, "__wrapped__"))

    def test_instrumentation_dependencies(self) -> None:
        deps = AsyncuaInstrumentor().instrumentation_dependencies()
        self.assertIn("asyncua >= 1.0.0", deps)
