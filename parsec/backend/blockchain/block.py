# Parsec Cloud (https://parsec.cloud) Copyright (c) AGPLv3 2016-2021 Scille SAS

from uuid import UUID
import attr

from parsec.api.protocol import DeviceID, OrganizationID
from parsec.api.protocol import RealmRole
from parsec.backend.realm import BaseRealmComponent, RealmNotFoundError
from parsec.backend.blockstore import BaseBlockStoreComponent
from parsec.backend.block import (
    BaseBlockComponent,
    BlockAlreadyExistsError,
    BlockAccessError,
    BlockNotFoundError,
    BlockInMaintenanceError,
)


import requests
import base64
import json
from json import JSONEncoder, JSONDecoder


abci_addr = 'http://localhost:26657/'


@attr.s(auto_attribs=True)
class BlockMeta:
    realm_id: UUID
    size: int

"""
In order to store block in tendermint, we could use the following Encoder/Decoder for  BlockMeta and Block.

class BlockMetaDecoder(JSONDecoder):
    def decode(self, obj):
        json_obj = json.loads(obj)
        return BlockMeta(UUID(json_obj['realm_id']), int(json_obj['size']))

class BlockDecoder(JSONDecoder):
    def decode(self, obj):
        json_obj = json.loads(obj)
        return base64.b64decode(json_obj['blob'].replace(' ', '+'))

class Encoder(JSONEncoder):
    def default(self, obj):
        if isinstance(obj, BlockMeta):
            return {'realm_id': obj.realm_id.__str__(), 'size': obj.size.__str__()}
        if isinstance(obj, bytes):
            return {'blob': base64.b64encode(obj).decode('utf-8')}
"""

class BlockchainBlockComponent(BaseBlockComponent):
    def __init__(self):
        self._blockmetas = {}
        self._blockstore_component = None
        self._realm_component = None

    def register_components(
        self, blockstore: BaseBlockStoreComponent, realm: BaseRealmComponent, **other_components
    ):
        self._blockstore_component = blockstore
        self._realm_component = realm

    def _check_realm_read_access(self, organization_id, realm_id, user_id):
        can_read_roles = (
            RealmRole.OWNER,
            RealmRole.MANAGER,
            RealmRole.CONTRIBUTOR,
            RealmRole.READER,
        )
        self._check_realm_access(organization_id, realm_id, user_id, can_read_roles)

    def _check_realm_write_access(self, organization_id, realm_id, user_id):
        can_write_roles = (RealmRole.OWNER, RealmRole.MANAGER, RealmRole.CONTRIBUTOR)
        self._check_realm_access(organization_id, realm_id, user_id, can_write_roles)

    def _check_realm_access(self, organization_id, realm_id, user_id, allowed_roles):
        try:
            realm = self._realm_component._get_realm(organization_id, realm_id)
        except RealmNotFoundError:
            raise BlockNotFoundError(f"Realm `{realm_id}` doesn't exist")
        if realm.roles.get(user_id) not in allowed_roles:
            raise BlockAccessError()

        if realm.status.in_maintenance:
            raise BlockInMaintenanceError(f"Realm `{realm_id}` is currently under maintenance")

    async def read(
        self, organization_id: OrganizationID, author: DeviceID, block_id: UUID
    ) -> bytes:
        try:
            blockmeta = self._blockmetas[(organization_id, block_id)]
        except KeyError:
            raise BlockNotFoundError()
        """
        if meta_block_exists(organization_id, block_id):
            return BlockNotFoundError()
        else:
            blockmeta = retrieve_block_meta(organization_id, block_id)
        """
        self._check_realm_read_access(organization_id, blockmeta.realm_id, author.user_id)

        return await self._blockstore_component.read(organization_id, block_id)

    async def create(
        self,
        organization_id: OrganizationID,
        author: DeviceID,
        block_id: UUID,
        realm_id: UUID,
        block: bytes,
    ) -> None:
        self._check_realm_write_access(organization_id, realm_id, author.user_id)

        await self._blockstore_component.create(organization_id, block_id, block)

        self._blockmetas[(organization_id, block_id)] = BlockMeta(realm_id, len(block))
        """
        key = create_key_block_meta(organization_id, block_id)
        broadcast_tx(key, json.dumps(BlockMeta(realm_id, len(block)), cls=Encoder))
        """

class BlockchainBlockStoreComponent(BaseBlockStoreComponent):
    def __init__(self):
        self._blocks = {}

    async def read(self, organization_id: OrganizationID, block_id: UUID) -> bytes:
        try:
            return self._blocks[(organization_id, block_id)]
        except KeyError:
            raise BlockNotFoundError()
        """
        if block_exists(organization_id, block_id):
            raise BlockNotFoundError()
        else:
            return retrieve_block(organization_id, block_id)
        """

    async def create(self, organization_id: OrganizationID, block_id: UUID, block: bytes) -> None:

        key = (organization_id, block_id)
        if key in self._blocks:
            # Should not happen if client play with uuid randomness
            raise BlockAlreadyExistsError()

        self._blocks[key] = block
        """
        if block_exists(organization_id, block_id):
            raise BlockAlreadyExistsError()
        else:
            key = create_key_block(organization_id, block_id)
            broadcast_tx(key, json.dumps(block, cls=Encoder))
        """

def create_key_block_meta(organization_id: OrganizationID, block_id: UUID):
    return '(block_meta, ' + organization_id.__str__() + ', ' + block_id.__str__() + ')'

def create_key_block(organization_id: OrganizationID, block_id: UUID):
    return '(block, ' + organization_id.__str__() + ', ' + block_id.__str__() + ')'

def retrieve_block_meta(organization_id: OrganizationID, block_id: UUID):
    key = create_key_block_meta(organization_id, block_id)
    raw_rep = retrieve_tx(key)
    return BlockMetaDecoder().decode(raw_rep, )

def retrieve_tx(key):
    cmd = abci_addr + 'abci_query?data="' + key + '"'
    req = requests.get(cmd)
    raw_rep = req.json()
    raw_rep = base64.b64decode(raw_rep['result']['response']['value']).decode('utf-8')
    return raw_rep.replace('\'', '\"')

def broadcast_tx(key, value):
    cmd = abci_addr + 'broadcast_tx_commit?tx="Key%3F' + key + '%26Value%3F' + value.replace('\"', '\'') + '"'
    req = requests.get(cmd)

def meta_block_exists(organization_id: OrganizationID, block_id: UUID):
    raw_rep = retrieve_tx(create_key_block_meta(organization_id, block_id))
    return True if raw_rep != "0" else False

def block_exists(organization_id: OrganizationID, block_id: UUID):
    raw_rep = retrieve_tx(create_key_block(organization_id, block_id))
    return True if raw_rep != "0" else False

def retrieve_block(organization_id: OrganizationID, block_id: UUID):
    key = create_key_block(organization_id, block_id)
    raw_rep = retrieve_tx(key)
    return BlockDecoder().decode(raw_rep, )
