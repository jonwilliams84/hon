"""Runtime patches for pyhon-revived and awscrt.

Two patches, both applied once from ``async_setup_entry`` via
``apply_pyhon_patches()``:

1. **awscrt metrics crash** — awscrt 0.35.0's ``_create_metrics_mqtt5`` calls
   ``_get_encoded_feature_list`` which accesses
   ``client_options.tls_ctx._certificate_source``. This attribute doesn't exist
   on ``ClientTlsContext`` in this version, causing ``AttributeError`` on every
   MQTT5 client creation — i.e. the hon integration can never set up. The patch
   replaces ``_create_metrics_mqtt5`` with a safe no-op that skips the feature
   list entirely (metrics are telemetry only, not functional). Remove when
   awscrt fixes the attribute access in a version pinned by manifest.json.

2. **pyhon-revived auth retry** — pyhon-revived 0.19.0's
   ``HonConnectionHandler._intercept`` retries a request up to two times on auth
   failure (loop 0: refresh token, loop 1: full re-login), but its final branch
   (``elif loop >= 2``) raises ``HonAuthenticationError`` *without checking the
   response status*. So when the loop-2 retry actually succeeds (HTTP 200, the
   appliance command/poll is accepted by the server), the successful response is
   discarded and an exception is raised back to Home Assistant. The patch
   reinstates the success path: it only treats ``loop >= 2`` as a failure when
   the response is *still* a 401/403.
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


def _patch_awscrt_metrics() -> None:
    """Disable awscrt's broken MQTT5 metrics telemetry.

    awscrt 0.35.0 crashes in ``_create_metrics_mqtt5`` →
    ``_get_encoded_feature_list`` because it accesses
    ``tls_ctx._certificate_source`` which doesn't exist on
    ``ClientTlsContext``. Metrics are AWS telemetry (feature reporting),
    not functional — safe to skip entirely.
    """
    import awscrt.aws_iot_metrics as metrics_mod
    import awscrt.mqtt5 as mqtt5_mod

    def _safe_create_metrics_mqtt5(client_options: object) -> object:  # noqa: ANN401
        return metrics_mod._create_metrics(
            getattr(client_options, "metrics", None), ""
        )

    # Patch both: aws_iot_metrics (source) AND mqtt5 (has its own imported binding)
    metrics_mod._create_metrics_mqtt5 = _safe_create_metrics_mqtt5
    mqtt5_mod._create_metrics_mqtt5 = _safe_create_metrics_mqtt5
    _LOGGER.debug("Patched awscrt _create_metrics_mqtt5 (telemetry disabled)")


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
    """Monkeypatch pyhon-revived and awscrt. Idempotent; safe to call on every setup."""
    global _PATCHED
    if _PATCHED:
        return
    # Patch awscrt FIRST — the MQTT5 client crash happens during Hon().create()
    _patch_awscrt_metrics()
    HonConnectionHandler._intercept = _intercept  # type: ignore[method-assign]
    _PATCHED = True
    _LOGGER.debug(
        "Applied runtime patches: awscrt metrics disabled, "
        "pyhon-revived _intercept fixed (successful retry on loop>=2 no longer discarded)"
    )
