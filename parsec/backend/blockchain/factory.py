# Parsec Cloud (https://parsec.cloud) Copyright (c) AGPLv3 2016-2021 Scille SAS

import math
from enum import Enum
from typing import Tuple, Dict

import trio
from async_generator import asynccontextmanager

from parsec.event_bus import EventBus
from parsec.utils import open_service_nursery
from parsec.backend.config import BackendConfig
from parsec.backend.blockstore import blockstore_factory
from parsec.backend.events import EventsComponent
from parsec.backend.blockchain.organization import BlockchainOrganizationComponent
from parsec.backend.blockchain.ping import BlockchainPingComponent
from parsec.backend.blockchain.user import BlockchainUserComponent
from parsec.backend.blockchain.invite import BlockchainInviteComponent
from parsec.backend.blockchain.message import BlockchainMessageComponent
from parsec.backend.blockchain.realm import BlockchainRealmComponent
from parsec.backend.blockchain.vlob import BlockchainVlobComponent
from parsec.backend.blockchain.block import BlockchainBlockComponent
from parsec.backend.webhooks import WebhooksComponent
from parsec.backend.http import HTTPComponent

from parsec.backend.backend_events import BackendEvent


import requests

@asynccontextmanager
async def components_factory(config: BackendConfig, event_bus: EventBus):
    send_events_channel, receive_events_channel = trio.open_memory_channel[
        Tuple[Enum, Dict[str, object]]
    ](math.inf)

    async def _send_event(event: Enum, **kwargs):
        await send_events_channel.send((event, kwargs))

    async def _dispatch_event():
        async for event, kwargs in receive_events_channel:
            await trio.sleep(0)
            event_bus.send(event, **kwargs)

    webhooks = WebhooksComponent(config)
    http = HTTPComponent(config)
    organization = BlockchainOrganizationComponent(_send_event, webhooks)
    user = BlockchainUserComponent(_send_event, event_bus)
    invite = BlockchainInviteComponent(_send_event, event_bus, config)
    message = BlockchainMessageComponent(_send_event)
    realm = BlockchainRealmComponent(_send_event)
    vlob = BlockchainVlobComponent(_send_event)
    ping = BlockchainPingComponent(_send_event)
    block = BlockchainBlockComponent()
    blockstore = blockstore_factory(config.blockstore_config)
    events = EventsComponent(realm, send_event=_send_event)

    components = {
        "events": events,
        "webhooks": webhooks,
        "http": http,
        "organization": organization,
        "user": user,
        "invite": invite,
        "message": message,
        "realm": realm,
        "vlob": vlob,
        "ping": ping,
        "block": block,
        "blockstore": blockstore,
    }
    for component in components.values():
        method = getattr(component, "register_components", None)
        if method is not None:
            method(**components)

    async with open_service_nursery() as nursery:
        nursery.start_soon(_dispatch_event)
        try:
            yield components

        finally:
            nursery.cancel_scope.cancel()
