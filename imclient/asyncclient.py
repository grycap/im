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

import asyncio
import os
from optparse import Values
from typing import Any, Dict, List, Optional, Union

import httpx

from imclient.imclient import IMClient, DescTypes

#: Default per-request timeout (in seconds) applied by the async client.
DEFAULT_TIMEOUT: float = 60.0

#: States that mean the infrastructure is still being deployed.
PENDING_STATES = ("pending", "running", "unknown")


class AsyncIMClient:
    """
    Asynchronous class to connect with the Infrastructure Manager.

    It mirrors the synchronous :py:class:`imclient.IMClient` API but performs the REST calls using
    :py:class:`httpx.AsyncClient`, reusing a single connection across calls. Unlike the synchronous
    client it applies a configurable per-request timeout.

    Error handling follows the same convention as the synchronous client: failures raise
    exceptions (:py:class:`httpx.HTTPStatusError` for HTTP errors, :py:class:`httpx.TransportError`
    for network errors) instead of returning ``(success, result)`` tuples, so callers can
    inspect the full response on failure.
    """

    def __init__(self, options: Values, auth_data: Union[str, List[Dict[str, str]], None],
                 args: List[str], timeout: Optional[float] = None,
                 transport: Optional[httpx.AsyncBaseTransport] = None) -> None:
        self.args: List[str] = args
        self.options: Values = options
        self.auth_data: Union[str, List[Dict[str, str]], None] = auth_data
        self.rest_auth_data: str = IMClient.build_auth_data(auth_data)
        self.timeout: float = timeout if timeout is not None else DEFAULT_TIMEOUT
        self._client: httpx.AsyncClient = httpx.AsyncClient(verify=self.options.verify,
                                                            timeout=self.timeout,
                                                            transport=transport)

    @staticmethod
    def init_client(im_url: str, auth_data: Union[str, List[Dict[str, str]]], ssl_verify: bool = False,
                    timeout: Optional[float] = None,
                    transport: Optional[httpx.AsyncBaseTransport] = None) -> "AsyncIMClient":
        """
        Create and initialize the AsyncIMClient class.

        Arguments:
           - im_url(string): URL to the IM API.
           - auth_data(:py:class:`dict` of str objects): Authentication data to access cloud provider
                                                         (as returned by `read_auth_data` function).
           - ssl_verify(boolean): Flag to specify if ssl certificates must be validated. Default `False`.
           - timeout(float): Per-request timeout in seconds. Default
                             :py:data:`imclient.asyncclient.DEFAULT_TIMEOUT`.
           - transport(:py:class:`httpx.AsyncBaseTransport`): Optional custom async transport (useful
                                                              for testing). Default `None`.
        Returns(:py:class:`imclient.asyncclient.AsyncIMClient`): A client ready to interact with an IM instance.
        """
        options = {"force": False, "quiet": True, "name": None, "system_name": None}
        options["restapi"] = im_url
        options["verify"] = ssl_verify
        return AsyncIMClient(Values(options), auth_data, [], timeout, transport)

    async def __aenter__(self) -> "AsyncIMClient":
        return self

    async def __aexit__(self, exc_type, exc_value, traceback) -> None:
        await self.aclose()

    async def aclose(self) -> None:
        """
        Close the underlying HTTP connection pool.
        """
        await self._client.aclose()

    async def create(self, inf_desc: str, desc_type: DescTypes = "radl", asyncr: bool = False,
                     dry_run: bool = False) -> Any:
        """
        Create an infrastructure.

        Arguments:
           - inf_desc(string): Infrastructure description in RADL (plain or JSON) or TOSCA.
           - desc_type(string): Infrastructure description type ("radl", "json", "yaml" or "yml").
           - asyncr(boolean): Flag to specify if the creation call will be asynchronous.
                              Default `False`.
           - dry_run(boolean): Flag to specify if the creation call will be a dry run (i.e.,
                               no actual creation). Default `False`.
        Returns: The ID of the created infrastructure.
        Raises: :py:class:`httpx.HTTPStatusError` if the creation fails.
        """
        headers = {"Authorization": self.rest_auth_data}
        if desc_type == "json":
            headers["Content-Type"] = "application/json"
        elif desc_type in ("yaml", "yml"):
            headers["Content-Type"] = "text/yaml"
        url = "%s/infrastructures" % self.options.restapi
        params = {}
        if asyncr:
            params["async"] = "yes"
        if dry_run:
            params["dry_run"] = "yes"
        resp = await self._client.post(url, headers=headers, params=params, content=str(inf_desc))
        resp.raise_for_status()
        if dry_run:
            return resp.json()
        else:
            return os.path.basename(resp.text)

    async def get_infra_property(self, inf_id: str, prop: str) -> Any:
        """
        Get an infrastructure property.

        Arguments:
           - inf_id(string): Infrastructure ID.
           - prop(string): Property to get. Valid values: "radl", "contmsg", "state", "outputs".
        Returns: The value of the property.
        Raises: :py:class:`httpx.HTTPStatusError` if the operation fails.
        """
        headers = {"Authorization": self.rest_auth_data, "Accept": "application/json"}
        url = "%s/infrastructures/%s/%s" % (self.options.restapi, inf_id, prop)
        resp = await self._client.get(url, headers=headers)
        resp.raise_for_status()
        return resp.json()[prop]

    async def destroy(self, inf_id: str, asyncr: bool = False) -> None:
        """
        Destroy an infrastructure.

        Arguments:
           - inf_id(string): Infrastructure ID.
           - asyncr(boolean): Flag to specify if the deletion call will be asynchronous.
                              Default `False`.
        Raises: :py:class:`httpx.HTTPStatusError` if the deletion fails.
        """
        headers = {"Authorization": self.rest_auth_data}
        url = "%s/infrastructures/%s" % (self.options.restapi, inf_id)
        params = {}
        if self.options.force:
            params["force"] = "yes"
        if asyncr:
            params["async"] = "yes"
        resp = await self._client.delete(url, headers=headers, params=params)
        resp.raise_for_status()

    async def wait(self, inf_id: str, max_time: int = 36000, poll_interval: int = 30) -> str:
        """
        Wait until an infrastructure is configured or fails.

        Arguments:
           - inf_id(string): Infrastructure ID.
           - max_time(int): Maximum time to wait in seconds. Default 36000 (10h).
           - poll_interval(int): Time in seconds between state queries. Default 30.
        Returns(string): Final state message on success.
        Raises: :py:class:`TimeoutError` on timeout, :py:class:`RuntimeError` if the
                infrastructure reaches a final non-configured state.
        """
        unknown_count = 0
        waited = 0
        state = "pending"
        while state in PENDING_STATES and unknown_count < 3 and waited < max_time:
            try:
                res = await self.get_infra_property(inf_id, "state")
                state = res["state"]
            except Exception:
                state = "unknown"

            if state == "unknown":
                unknown_count += 1

            if state in PENDING_STATES:
                await asyncio.sleep(poll_interval)
                waited += poll_interval

        if state == "configured":
            return "The infrastructure is in state: %s" % state
        elif waited >= max_time:
            raise TimeoutError("Timeout waiting.")
        else:
            raise RuntimeError("The infrastructure is in state: %s" % state)

    async def create_wait_outputs(self, inf_desc: str, desc_type: DescTypes = "radl",
                                  max_time: int = 36000, poll_interval: int = 30) -> Dict[str, Any]:
        """
        Create an infrastructure, wait until it is configured and return its outputs.

        Arguments:
           - inf_desc(string): Infrastructure description in RADL (plain or JSON) or TOSCA.
           - desc_type(string): Infrastructure description type ("radl", "json", "yaml" or "yml").
           - max_time(int): Maximum time to wait in seconds. Default 36000 (10h).
           - poll_interval(int): Time in seconds between state queries. Default 30.
        Returns(dict): The infrastructure outputs (including the ``infid`` key).
        Raises: :py:class:`httpx.HTTPStatusError` if any HTTP step fails,
                :py:class:`TimeoutError` on wait timeout, :py:class:`RuntimeError` on wait failure.
        """
        inf_id = await self.create(inf_desc, desc_type)
        await self.wait(inf_id, max_time, poll_interval)
        outputs = await self.get_infra_property(inf_id, "outputs")
        outputs["infid"] = inf_id
        return outputs
