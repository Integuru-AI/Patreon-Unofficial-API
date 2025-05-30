import json

import aiohttp
from fake_useragent import UserAgent

from submodule_integrations.models.integration import Integration
from submodule_integrations.utils.errors import IntegrationAuthError, IntegrationAPIError


class PatreonIntegration(Integration):
    def __init__(self, token: str, network_requester=None, user_agent: str = UserAgent().random):
        super().__init__("patreon")
        self.token = token
        self.network_requester = network_requester
        self.user_agent = user_agent
        self.url = "https://www.patreon.com"

        self.headers = {
            "Host": "www.patreon.com",
            "User-Agent": self.user_agent,
            "Cookie": token
        }

    async def _make_request(
            self, method: str, url: str, **kwargs
    ) -> dict | str | bytes:
        if self.network_requester is not None:
            response = await self.network_requester.request(
                method, url, process_response=self._handle_response, **kwargs
            )
            return response
        else:
            async with aiohttp.ClientSession() as session:
                async with session.request(method, url, **kwargs) as response:
                    return await self._handle_response(response)

    async def _handle_response(self, response: aiohttp.ClientResponse):
        if response.status == 200:
            try:
                data = await response.json()
            except (json.decoder.JSONDecodeError, aiohttp.ContentTypeError):
                data = await response.text()

            return data

        if response.status == 401:
            raise IntegrationAuthError(
                "Patreon: Auth failed",
                response.status,
            )
        elif response.status == 400:
            raise IntegrationAPIError(
                self.integration_name,
                f"{response.reason}",
                response.status,
                response.reason,
            )
        else:
            raise IntegrationAPIError(
                self.integration_name,
                f"{await response.text()}",
                response.status,
                response.reason,
            )
