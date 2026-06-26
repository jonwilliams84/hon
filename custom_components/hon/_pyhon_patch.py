"""Runtime patch for pyhon-revived's authenticated request handler.

pyhon-revived 0.19.0's ``HonConnectionHandler._intercept`` retries a request up
to two times on auth failure (loop 0: refresh token, loop 1: full re-login), but
its final branch (``elif loop >= 2``) raises ``HonAuthenticationError`` *without
checking the response status*. So when the loop-2 retry actually succeeds
(HTTP 200, the appliance command/poll is accepted by the server), the successful
response is discarded and an exception is raised back to Home Assistant.

The visible effect after a token expires during idle: the first command "fails"
even though the unit received it, and the poll that triggers the re-auth leaves
entity states stale until the next cycle.

This module reinstates the success path on the final attempt: it only treats
``loop >= 2`` as a failure when the response is *still* a 401/403. Applied once
from ``async_setup_entry``; removable when fixed upstream.
"""

from __future__ import annotations

import json
import logging
from collections.abc import AsyncIterator
from contextlib import asynccontextmanager
from typing import Any

import aiohttp
from yarl import URL

from pyhon.connection.handler.hon import HonConnectionHandler
from pyhon.exceptions import HonAuthenticationError
from pyhon.typedefs import Callback

_LOGGER = logging.getLogger(__name__)

_PATCHED = False


@asynccontextmanager
async def _intercept(
    self: HonConnectionHandler,
    method: Callback,
    url: str | URL,
    *args: Any,
    **kwargs: Any,
) -> AsyncIterator[aiohttp.ClientResponse]:
    """Drop-in replacement for HonConnectionHandler._intercept.

    Identical to upstream except the final ``loop >= 2`` branch only raises when
    the response is still an auth error, so a successful retry is yielded.
    """
    loop: int = kwargs.pop("loop", 0)
    kwargs["headers"] = await self._check_headers(kwargs.get("headers", {}))
    async with method(url, *args, **kwargs) as response:
        if (
            self.auth.token_expires_soon or response.status in [401, 403]
        ) and loop == 0:
            _LOGGER.info("Try refreshing token...")
            await self.auth.refresh(self._refresh_token)
            async with self._intercept(
                method, url, *args, loop=loop + 1, **kwargs
            ) as result:
                yield result
        elif (
            self.auth.token_is_expired or response.status in [401, 403]
        ) and loop == 1:
            _LOGGER.warning(
                "%s - Error %s - %s",
                response.request_info.url,
                response.status,
                await response.text(),
            )
            await self.create()
            async with self._intercept(
                method, url, *args, loop=loop + 1, **kwargs
            ) as result:
                yield result
        elif loop >= 2 and response.status in [401, 403]:
            # Only give up if the final retry is STILL an auth failure. Upstream
            # raised here unconditionally, discarding a successful (200) retry.
            _LOGGER.error(
                "%s - Error %s - %s",
                response.request_info.url,
                response.status,
                await response.text(),
            )
            raise HonAuthenticationError("Login failure")
        else:
            try:
                await response.json()
                yield response
            except json.JSONDecodeError as exc:
                _LOGGER.warning(
                    "%s - JsonDecodeError %s - %s",
                    response.request_info.url,
                    response.status,
                    await response.text(),
                )
                raise HonAuthenticationError("Decode Error") from exc


def apply_pyhon_patches() -> None:
    """Monkeypatch pyhon-revived. Idempotent; safe to call on every setup."""
    global _PATCHED
    if _PATCHED:
        return
    HonConnectionHandler._intercept = _intercept  # type: ignore[method-assign]
    _PATCHED = True
    _LOGGER.debug(
        "Applied pyhon-revived _intercept patch "
        "(successful retry on loop>=2 no longer discarded)"
    )
