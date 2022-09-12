# import json
import asyncio
import hashlib
from time import time
from typing import Any
from contextlib import AbstractAsyncContextManager

import aiohttp
from aiohttp import hdrs
from aiohttp.client_exceptions import ClientResponseError
from aiohttp.typedefs import StrOrURL

from bbrain.iac import json
from bbrain.iac.ovh.config import config
from bbrain.iac.ovh.exceptions import (
    HTTPBadRequest,
    HTTPForbidden,
    HTTPMethodNotAllowed,
    HTTPNotFound,
    HTTPUnauthorized,
    InvalidRegion,
)
from yarl import URL

ENDPOINTS = {
    "ovh-eu": "https://eu.api.ovh.com/1.0",
    "ovh-us": "https://api.us.ovhcloud.com/1.0",
    "ovh-ca": "https://ca.api.ovh.com/1.0",
    "kimsufi-eu": "https://eu.api.kimsufi.com/1.0",
    "kimsufi-ca": "https://ca.api.kimsufi.com/1.0",
    "soyoustart-eu": "https://eu.api.soyoustart.com/1.0",
    "soyoustart-ca": "https://ca.api.soyoustart.com/1.0",
}


class ClientResponse(aiohttp.ClientResponse):
    def raise_for_status(self) -> None:
        try:
            super().raise_for_status()
        except ClientResponseError as err:
            if err.code == 400:
                raise HTTPBadRequest(*err.args) from err
            elif err.code == 401:
                raise HTTPUnauthorized(*err.args) from err
            elif err.code == 403:
                raise HTTPForbidden(*err.args) from err
            elif err.code == 404:
                raise HTTPNotFound(*err.args) from err
            elif err.code == 405:
                raise HTTPMethodNotAllowed(*err.args) from err
            elif err.code == 409:
                raise HTTPBadRequest(*err.args) from err
            raise


class Client(AbstractAsyncContextManager):
    _session: aiohttp.ClientSession | None = None
    _count: int = 0

    async def __aenter__(self):
        self.count = self.count + 1
        async with self.get("/auth/time", sign=False) as resp:
            server_time = int(await resp.text())
            self.time_delta = server_time - int(time())
        return self

    async def __aexit__(self, exc_type, exc, tb):
        self.count = self.count - 1
        if self.count == 0 and self.session is not None:
            return await self.session.close()
        return await asyncio.sleep(0)

    def __init__(self):
        self._endpoint = config.get("default", "endpoint")
        try:
            self._base_url = URL(ENDPOINTS[self._endpoint])
        except KeyError:
            raise InvalidRegion(
                "Unknown endpoint %s. Valid endpoints: %s",
                config.get("default", "endpoint"),
                ENDPOINTS.keys(),
            )

        self._consumer_key = config.get(self._endpoint, "consumer_key")
        self._application_key = config.get(self._endpoint, "application_key")
        self._application_secret = config.get(self._endpoint, "application_secret")

        if self.session is None:
            self.session = aiohttp.ClientSession(
                self._base_url.origin(),
                headers={"X-Ovh-Application": self._application_key},
                json_serialize=json.dumps,
                response_class=ClientResponse,
                raise_for_status=True,
            )

    def get(self, url: StrOrURL, *, allow_redirects: bool = True, **kwargs: Any):
        """Perform HTTP GET request."""
        return self.__call(
            hdrs.METH_GET, url, allow_redirects=allow_redirects, **kwargs
        )

    def options(self, url: StrOrURL, *, allow_redirects: bool = True, **kwargs: Any):
        """Perform HTTP OPTIONS request."""
        return self.__call(
            hdrs.METH_OPTIONS, url, allow_redirects=allow_redirects, **kwargs
        )

    def head(self, url: StrOrURL, *, allow_redirects: bool = False, **kwargs: Any):
        """Perform HTTP HEAD request."""
        return self.__call(
            hdrs.METH_HEAD, url, allow_redirects=allow_redirects, **kwargs
        )

    def post(self, url: StrOrURL, *, data: Any = None, **kwargs: Any):
        """Perform HTTP POST request."""
        return self.__call(hdrs.METH_POST, url, data=data, **kwargs)

    def put(self, url: StrOrURL, *, data: Any = None, **kwargs: Any):
        """Perform HTTP PUT request."""
        return self.__call(hdrs.METH_PUT, url, data=data, **kwargs)

    def patch(self, url: StrOrURL, *, data: Any = None, **kwargs: Any):
        """Perform HTTP PATCH request."""
        return self.__call(hdrs.METH_PATCH, url, data=data, **kwargs)

    def delete(self, url: StrOrURL, **kwargs: Any):
        """Perform HTTP DELETE request."""
        return self.__call(hdrs.METH_DELETE, url, **kwargs)

    def __call(self, method: str, url: StrOrURL, **kwargs):
        url = URL(url)
        if not url.path.startswith(self._base_url.path):
            url = URL(self._base_url.path + url.path)

        # Sign all requests by default
        if kwargs.pop("sign", True):
            if "headers" not in kwargs:
                kwargs["headers"] = {}
            kwargs["headers"].update(self.__sign(method, url, **kwargs))

        return self.session.request(method, url, **kwargs)

    @property
    def session(self):
        return Client._session

    @session.setter
    def session(self, value):
        Client._session = value

    @property
    def count(self):
        return Client._count

    @count.setter
    def count(self, value):
        Client._count = value

    def __sign(self, method, url: URL, **kwargs):
        now = str(int(time()) + self.time_delta)
        headers = {}
        body = kwargs.get("data", "")
        json_data = kwargs.get("json", None)

        if json_data or body:
            headers["Content-Type"] = "application/json"

        if json_data:
            body = json.dumps(json_data)

        if body is None:
            body = ""

        _payload = [
            self._application_secret,
            self._consumer_key,
            method.upper(),
            str(self._base_url.join(url)),
            body,
            now,
        ]

        signature = hashlib.sha1()
        signature.update("+".join(_payload).encode("utf-8"))

        headers.update(
            {
                "X-Ovh-Consumer": self._consumer_key,
                "X-Ovh-Timestamp": now,
                "X-Ovh-Signature": "$1$" + signature.hexdigest(),
            }
        )

        return headers
