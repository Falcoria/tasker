import httpx
from typing import Optional, Dict, Any


class BaseConnector:
    """Async base class for all connectors to provide request handling."""

    def __init__(self, base_url: str, auth_token: str):
        self.base_url = base_url.rstrip("/")
        self.auth_token = auth_token
        self.headers = {"Authorization": f"Bearer {self.auth_token}"}
        self.client = httpx.AsyncClient(
            base_url=self.base_url,
            headers=self.headers,
            verify=False  # You can toggle this based on config
        )

    async def make_request(
        self,
        endpoint: str,
        method: str = "GET",
        query_params: Optional[Dict[str, Any]] = None,
        json_body: Optional[Dict[str, Any]] = None,
        timeout: int = 20,
        files: Optional[Dict[str, Any]] = None,
    ) -> httpx.Response:
        """Perform HTTP request. Raise RuntimeError on failure."""
        url = f"/{endpoint.lstrip('/')}"  # already handled by base_url in client

        try:
            if method in ["GET", "DELETE"]:
                response = await self.client.request(
                    method=method,
                    url=url,
                    params=query_params,
                    timeout=timeout,
                )
            elif files is not None:
                response = await self.client.post(
                    url=url,
                    files=files,
                    params=query_params,
                    timeout=timeout,
                )
            elif method in ["POST", "PUT"]:
                response = await self.client.request(
                    method=method,
                    url=url,
                    params=query_params,
                    json=json_body,
                    timeout=timeout,
                )
            else:
                raise ValueError(f"Unsupported HTTP method: {method}")

            response.raise_for_status()
            return response

        except httpx.ConnectError as e:
            raise RuntimeError(f"Server is unreachable: {e}") from e

        except httpx.TimeoutException as e:
            raise RuntimeError(f"Request timed out: {e}") from e

        except httpx.HTTPStatusError as e:
            raise RuntimeError(f"HTTP {e.response.status_code}: {e.response.text}") from e

        except httpx.RequestError as e:
            raise RuntimeError(f"Request failed: {e}") from e

        except Exception as e:
            raise RuntimeError(f"Unexpected error during request: {e}") from e

    def _handle_response(
        self,
        response: httpx.Response,
        expect_json: bool = True,
        return_content: bool = False,
    ):
        if return_content:
            return response.content

        if not expect_json:
            return response.status_code

        try:
            return response.json()
        except Exception:
            return None

    async def close(self):
        await self.client.aclose()
