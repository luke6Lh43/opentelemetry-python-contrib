OpenTelemetry asyncua Instrumentation
=====================================

|pypi|

.. |pypi| image:: https://badge.fury.io/py/opentelemetry-instrumentation-asyncua.svg
   :target: https://pypi.org/project/opentelemetry-instrumentation-asyncua/

This library allows tracing OPC UA operations made by the
`asyncua <https://github.com/FreeOpcUa/opcua-asyncio>`_ library.

Installation
------------

::

     pip install opentelemetry-instrumentation-asyncua

Usage
-----

.. code-block:: python

    import asyncio
    from asyncua import Client
    from opentelemetry.instrumentation.asyncua import AsyncUAInstrumentor

    AsyncUAInstrumentor().instrument()

    async def main():
        async with Client(url="opc.tcp://localhost:4840") as client:
            node = client.get_node("ns=3;i=1001")
            value = await node.read_value()
            print(value)

    asyncio.run(main())

Each call to ``Node.read_value()`` produces an ``opcua.read`` span.

References
----------

* `OpenTelemetry Project <https://opentelemetry.io/>`_
* `OpenTelemetry Python Examples <https://github.com/open-telemetry/opentelemetry-python/tree/main/docs/examples>`_