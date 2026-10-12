#! /usr/bin/env python
#
# IM - Infrastructure Manager
# Copyright (C) 2011 - GRyCAP - Universitat Politecnica de Valencia
#
# This program is free software: you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation, either version 3 of the License, or
# (at your option) any later version.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program.  If not, see <http://www.gnu.org/licenses/>.

import sys
import unittest

import httpx

sys.path.append("..")
sys.path.append(".")

from imclient import IMClient, AsyncIMClient


AUTH = [
    {"type": "InfrastructureManager", "username": "someuser", "password": "somepass"},
    {"id": "one", "type": "OpenNebula", "host": "server:2633", "username": "user", "password": "pass"},
]

IM_URL = "https://im.example.com/im"

OUTPUT_PATHS = ("/im/infrastructures/infid/outputs", "/im/infrastructures/inf1/outputs")


class TestAsyncClient(unittest.IsolatedAsyncioTestCase):
    """
    Class to test the IM async client
    """

    @staticmethod
    def get_transport(recorded=None):
        """
        Build a httpx.MockTransport that emulates the subset of the IM REST API used by the client.
        """
        if recorded is None:
            recorded = []

        def handler(request):
            recorded.append(request)
            path = request.url.path
            if request.method == "POST" and path == "/im/infrastructures":
                return httpx.Response(200, text="http://localhost/im/infrastructures/inf1")
            elif request.method == "GET" and path == "/im/infrastructures/infid/state":
                return httpx.Response(200, json={"state": {"state": "running", "vm_states": {"vm1": "running"}}})
            elif request.method == "GET" and path == "/im/infrastructures/inf1/state":
                return httpx.Response(200, json={"state": {"state": "configured", "vm_states": {"vm1": "configured"}}})
            elif request.method == "GET" and path in OUTPUT_PATHS:
                return httpx.Response(200, json={"outputs": {"output1": "value1", "output2": "value2"}})
            elif request.method == "DELETE" and path == "/im/infrastructures/infid":
                return httpx.Response(200, text="")
            return httpx.Response(404, text="not found")

        return httpx.MockTransport(handler), recorded

    async def test_auth_header_parity(self):
        """
        The async client must build exactly the same Authorization header as the sync client.
        """
        sync = IMClient.init_client(IM_URL, AUTH)
        async_client = AsyncIMClient.init_client(IM_URL, AUTH, transport=httpx.MockTransport(lambda r: None))
        self.assertEqual(sync.rest_auth_data, async_client.rest_auth_data)
        await async_client.aclose()

    async def test_auth_header_multiline_parity(self):
        """
        Newlines inside auth values must be escaped exactly as in the sync client.
        """
        auth = [{"type": "InfrastructureManager", "username": "user", "password": "line1\nline2"}]
        sync = IMClient.init_client(IM_URL, auth)
        async_client = AsyncIMClient.init_client(IM_URL, auth, transport=httpx.MockTransport(lambda r: None))
        self.assertEqual(sync.rest_auth_data, async_client.rest_auth_data)
        self.assertIn("password = line1\\\\nline2;", async_client.rest_auth_data)
        await async_client.aclose()

    async def test_auth_header_string_parity(self):
        """
        A string auth value must be passed through verbatim.
        """
        sync = IMClient.init_client(IM_URL, "Bearer sometoken")
        async_client = AsyncIMClient.init_client(IM_URL, "Bearer sometoken",
                                                 transport=httpx.MockTransport(lambda r: None))
        self.assertEqual(sync.rest_auth_data, async_client.rest_auth_data)
        self.assertEqual(async_client.rest_auth_data, "Bearer sometoken")
        await async_client.aclose()

    async def test_create(self):
        """
        Test create operation: body verbatim, content type and inf_id parsing.
        """
        transport, recorded = self.get_transport()
        desc = "description desc (name = 'test')\nsystem node ()"
        async with AsyncIMClient.init_client(IM_URL, AUTH, transport=transport) as client:
            success, inf_id = await client.create(desc, "yaml")

        self.assertTrue(success)
        self.assertEqual(inf_id, "inf1")
        self.assertEqual(recorded[0].content.decode(), desc)
        self.assertEqual(recorded[0].headers["Content-Type"], "text/yaml")
        self.assertEqual(recorded[0].headers["Authorization"], IMClient.build_auth_data(AUTH))

    async def test_create_json(self):
        """
        Test create operation with a JSON description.
        """
        transport, recorded = self.get_transport()
        async with AsyncIMClient.init_client(IM_URL, AUTH, transport=transport) as client:
            success, inf_id = await client.create('{"description": "test"}', "json")

        self.assertTrue(success)
        self.assertEqual(inf_id, "inf1")
        self.assertEqual(recorded[0].headers["Content-Type"], "application/json")

    async def test_get_state(self):
        """
        Test get_infra_property for the state property.
        """
        transport, recorded = self.get_transport()
        async with AsyncIMClient.init_client(IM_URL, AUTH, transport=transport) as client:
            success, value = await client.get_infra_property("infid", "state")

        self.assertTrue(success)
        self.assertEqual(value, {"state": "running", "vm_states": {"vm1": "running"}})
        self.assertEqual(recorded[0].headers["Accept"], "application/json")

    async def test_get_outputs(self):
        """
        Test get_infra_property for the outputs property.
        """
        transport, _ = self.get_transport()
        async with AsyncIMClient.init_client(IM_URL, AUTH, transport=transport) as client:
            success, value = await client.get_infra_property("infid", "outputs")

        self.assertTrue(success)
        self.assertEqual(value, {"output1": "value1", "output2": "value2"})

    async def test_destroy(self):
        """
        Test destroy operation.
        """
        transport, recorded = self.get_transport()
        async with AsyncIMClient.init_client(IM_URL, AUTH, transport=transport) as client:
            success, _ = await client.destroy("infid")

        self.assertTrue(success)
        self.assertEqual(recorded[0].method, "DELETE")
        self.assertEqual(recorded[0].url.path, "/im/infrastructures/infid")

    async def test_non_200(self):
        """
        Test that a non-200 response is reported as (False, error).
        """
        transport, _ = self.get_transport()
        async with AsyncIMClient.init_client(IM_URL, AUTH, transport=transport) as client:
            success, error = await client.get_infra_property("unknown", "outputs")

        self.assertFalse(success)
        self.assertIn("404", str(error))

    async def test_timeout_applied(self):
        """
        Test that the configured timeout is applied and that a timeout is reported as (False, error).
        """
        def handler(request):
            raise httpx.ConnectTimeout("timed out")

        async with AsyncIMClient.init_client(IM_URL, AUTH, timeout=5.0,
                                             transport=httpx.MockTransport(handler)) as client:
            self.assertEqual(client._client.timeout.connect, 5.0)
            success, error = await client.create("system node ()")

        self.assertFalse(success)
        self.assertIn("timed out", str(error))

    async def test_wait(self):
        """
        Test the wait operation until the infrastructure is configured.
        """
        transport, _ = self.get_transport()
        async with AsyncIMClient.init_client(IM_URL, AUTH, transport=transport) as client:
            success, result = await client.wait("inf1", poll_interval=0)

        self.assertTrue(success)
        self.assertEqual(result, "The infrastructure is in state: configured")

    async def test_create_wait_outputs(self):
        """
        Test the create_wait_outputs operation.
        """
        transport, _ = self.get_transport()
        async with AsyncIMClient.init_client(IM_URL, AUTH, transport=transport) as client:
            success, outputs = await client.create_wait_outputs("system node ()", poll_interval=0)

        self.assertTrue(success)
        self.assertEqual(outputs, {"infid": "inf1", "output1": "value1", "output2": "value2"})

    async def test_aclose(self):
        """
        Test that aclose closes the connection pool.
        """
        client = AsyncIMClient.init_client(IM_URL, AUTH, transport=httpx.MockTransport(lambda r: None))
        await client.aclose()
        self.assertTrue(client._client.is_closed)


if __name__ == '__main__':
    unittest.main()
