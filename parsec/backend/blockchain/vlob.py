# Parsec Cloud (https://parsec.cloud) Copyright (c) AGPLv3 2016-2021 Scille SAS

import attr
import pendulum
from uuid import UUID
from typing import List, Tuple, Dict, Optional

from parsec.backend.backend_events import BackendEvent
from parsec.api.protocol import DeviceID, OrganizationID
from parsec.api.protocol import RealmRole
from parsec.backend.realm import BaseRealmComponent, RealmNotFoundError
from parsec.backend.vlob import (
    BaseVlobComponent,
    VlobAccessError,
    VlobVersionError,
    VlobTimestampError,
    VlobNotFoundError,
    VlobAlreadyExistsError,
    VlobEncryptionRevisionError,
    VlobInMaintenanceError,
    VlobNotInMaintenanceError,
)

import requests
import base64
import json
from json import JSONEncoder, JSONDecoder

abci_addr = 'http://localhost:26657/'


@attr.s
class Vlob:
    realm_id: UUID = attr.ib()
    data: List[Tuple[bytes, DeviceID, pendulum.DateTime]] = attr.ib(factory=list)

    @property
    def current_version(self):
        return len(self.data)

    def __eq__(self, other):
        if isinstance(other, Vlob):
            for t1, t2 in zip(other.data, self.data):
                if t1[0] != t2[0] or t1[1] != t2[1] or t1[2] != t2[2]:
                    return False
            if other.realm_id != self.realm_id:
                return False
            return True
        return False


class VlobDecoder(JSONDecoder):
    def decode(self, obj, **kwargs):
        json_vlob = json.loads(obj)
        vlob = Vlob(UUID(json_vlob['realm_id']))
        # ' ' need to replace '+' otherwise a deserialisation happends
        for elt in json_vlob['data']:
            if '.' in elt['timestamp']:
                vlob.data.append((base64.b64decode(elt['blob'].replace(' ', '+')), DeviceID(elt['author']),
                                  pendulum.from_format(elt['timestamp'].replace(' ', '+'),
                                                       'YYYY-MM-DDTHH:mm:ss.SSSSSSZ')))
            else:
                vlob.data.append((base64.b64decode(elt['blob'].replace(' ', '+')), DeviceID(elt['author']),
                                  pendulum.from_format(elt['timestamp'].replace(' ', '+'), 'YYYY-MM-DDTHH:mm:ssZ')))
        return vlob


class VlobKeys:
    # data: List[Tuple[organization_id, vlob_id]]
    data: List[Tuple[OrganizationID, UUID]]

    def __init__(self, data=None):
        if data is None:
            data = []
        self.data = data


class VlobKeysDecoder(JSONDecoder):
    def decode(self, obj, **kwargs):
        json_vlob_keys = json.loads(obj)
        list_data = []
        for elt in json_vlob_keys['data']:
            list_data.append((OrganizationID(elt['organization_id']), UUID(elt['vlob_id'])))
        return VlobKeys(list_data)


class Reencryption:
    def __init__(self, realm_id, organization_id, vlobs):
        self.realm_id = realm_id
        self.organization_id = organization_id
        self._original_vlobs = vlobs
        self._todo = {}
        self._done = {}
        for vlob_id, vlob in vlobs.items():
            for index, (data, _, _) in enumerate(vlob.data):
                version = index + 1
                self._todo[(vlob_id, version)] = data
        self._total = len(self._todo)

    def __eq__(self, other):
        if isinstance(other, Reencryption):
            if self.realm_id != other.realm_id:
                return False
            if self.organization_id != other.organization_id:
                return False
            if self._original_vlobs != other._original_vlobs:
                return False
            return True
        return False

    def get_reencrypted_vlobs(self):
        assert self.is_finished()
        vlobs = {}
        for (vlob_id, version), data in sorted(self._done.items()):
            try:
                (_, author, timestamp) = self._original_vlobs[vlob_id].data[version - 1]

            except KeyError:
                raise VlobNotFoundError()

            if vlob_id not in vlobs:
                vlobs[vlob_id] = Vlob(self.realm_id, [(data, author, timestamp)])
            else:
                vlobs[vlob_id].data.append((data, author, timestamp))
            assert len(vlobs[vlob_id].data) == version

        return vlobs

    def is_finished(self):
        return not self._todo

    def get_batch(self, size):
        batch = []
        for (vlob_id, version), data in self._todo.items():
            if (vlob_id, version) in self._done:
                continue
            batch.append((vlob_id, version, data))
        return batch[:size]

    def save_batch(self, batch):
        for vlob_id, version, data in batch:
            key = (vlob_id, version)
            if key in self._done:
                continue
            try:
                del self._todo[key]
            except KeyError:
                raise VlobNotFoundError()
            self._done[key] = data

        return self._total, len(self._done)


@attr.s
class Changes():
    checkpoint: int = attr.ib(default=0)
    changes: Dict[UUID, Tuple[DeviceID, int, int]] = attr.ib(factory=dict)
    reencryption: Reencryption = attr.ib(default=None)

    def __init__(self, checkpoint=0, changes=None, reencryption=None):
        if changes is None:
            changes = {}
        self.checkpoint = checkpoint
        self.changes = changes
        self.reencryption = reencryption

    def __eq__(self, other):
        if isinstance(other, Changes):
            if self.checkpoint != other.checkpoint:
                return False
            if self.changes != other.changes:
                return False
            if self.reencryption != other.reencryption:
                return False
            return True
        return False


class ChangesDecoder(JSONDecoder):
    def decode(self, obj, **kwargs):
        json_changes = json.loads(obj)
        dict_changes = {}
        for k, v in json_changes['changes'].items():
            dict_changes[UUID(k)] = (DeviceID(v['author']), int(v['checkpoint']), int(v['src_version']))

        # reconstruct reencryption
        if json_changes['reencryption'] == 'None':
            return Changes(int(json_changes['checkpoint']), dict_changes, None)
        else:
            items = []
            vlob_keys = retrieve_set_vlob_keys()
            for k in vlob_keys.data:
                items.append(((k[0], k[1]), retrieve_vlob(k[0], k[1])))
            realm_vlobs = {
                vlob_id: vlob
                for (orgid, vlob_id), vlob in items
                if orgid == OrganizationID(json_changes['reencryption'][1]) and vlob.realm_id == UUID(
                    json_changes['reencryption'][0])
            }
            return Changes(int(json_changes['checkpoint']), dict_changes,
                           Reencryption(UUID(json_changes['reencryption'][0]),
                                        OrganizationID(json_changes['reencryption'][1]), realm_vlobs))


class ChangesKeys:
    # data: List[Tuple[organization_id, realm_id]]
    data: List[Tuple[OrganizationID, UUID]]

    def __init__(self, data=None):
        if data is None:
            data = []
        self.data = data


class ChangesKeysDecoder(JSONDecoder):
    def decode(self, obj, **kwargs):
        json_obj = json.loads(obj)
        list_data = []
        for elt in json_obj['data']:
            list_data.append((OrganizationID(elt['organization_id']), UUID(elt['realm_id'])))
        return ChangesKeys(list_data)


class Encoder(JSONEncoder):
    def default(self, obj):
        if isinstance(obj, Vlob):
            data_to_json_list = []
            for d in obj.data:
                data_to_json_list.append({'blob': base64.b64encode(d[0]).decode('utf-8'), 'author': d[1].__str__(),
                                          'timestamp': d[2].__str__()})
            return {'realm_id': obj.realm_id.__str__(), 'data': data_to_json_list}

        if isinstance(obj, Changes):
            dict_changes = {}
            for k, v in obj.changes.items():
                dict_changes[k.__str__()] = {'author': v[0].__str__(), 'checkpoint': str(v[1]),
                                             'src_version': str(v[2])}
            if obj.reencryption == None:
                return {'checkpoint': obj.checkpoint.__str__(), 'changes': dict_changes, 'reencryption': 'None'}
            else:
                return {'checkpoint': obj.checkpoint.__str__(), 'changes': dict_changes,
                        'reencryption': [obj.reencryption.realm_id.__str__(),
                                         obj.reencryption.organization_id.__str__()]}

        if isinstance(obj, VlobKeys):
            keys_to_json_list = []
            for d in obj.data:
                keys_to_json_list.append({'organization_id': d[0].__str__(), 'vlob_id': d[1].__str__()})
            return {'data': keys_to_json_list}

        if isinstance(obj, ChangesKeys):
            keys_to_json_list = []
            for d in obj.data:
                keys_to_json_list.append({'organization_id': d[0].__str__(), 'realm_id': d[1].__str__()})
            return {'data': keys_to_json_list}


class BlockchainVlobComponent(BaseVlobComponent):
    def __init__(self, send_event):
        self._send_event = send_event
        self._realm_component = None
        reset_database()

    def register_components(self, realm: BaseRealmComponent, **other_components):
        self._realm_component = realm

    # this method doesn't need to be a self one but we doesn't change it to avoid error from call from other component
    def _maintenance_reencryption_start_hook(self, organization_id, realm_id, encryption_revision):
        changes = retrieve_changes(organization_id, realm_id)

        assert not changes.reencryption
        realm_vlobs = {
            vlob_id: vlob
            for (orgid, vlob_id), vlob in self._get_items()
            if orgid == organization_id and vlob.realm_id == realm_id
        }
        changes.reencryption = Reencryption(realm_id, organization_id, realm_vlobs)
        broadcast_tx(create_key_changes(organization_id, realm_id), json.dumps(changes, cls=Encoder))

    # this method doesn't need to be a self one but we doesn't change it to avoid error from call from other component
    def _maintenance_reencryption_is_finished_hook(
        self, organization_id, realm_id, encryption_revision
    ):
        changes = retrieve_changes(organization_id, realm_id)
        assert changes.reencryption
        if not changes.reencryption.is_finished():
            return False

        realm_vlobs = changes.reencryption.get_reencrypted_vlobs()
        for vlob_id, vlob in realm_vlobs.items():
            broadcast_tx(create_key_vlob(organization_id, vlob_id), json.dumps(vlob, cls=Encoder))
        changes.reencryption = None
        broadcast_tx(create_key_changes(organization_id, realm_id), json.dumps(changes, cls=Encoder))
        return True

    # this method doesn't need to be a self one but we doesn't change it to avoid error from call from other component
    def _get_items(self):
        items = []
        vlob_keys = retrieve_set_vlob_keys()
        for k in vlob_keys.data:
            items.append(((k[0], k[1]), get_vlob(k[0], k[1])))
        return items

    # this method doesn't need to be a self one but we doesn't change it to avoid error from call from other component
    def _get_values(self):
        values = []
        vlob_keys = retrieve_set_vlob_keys()
        for k in vlob_keys.data:
            values.append((get_vlob(k[0], k[1])))
        return values

    def _check_realm_read_access(self, organization_id, realm_id, user_id, encryption_revision):
        can_read_roles = (
            RealmRole.OWNER,
            RealmRole.MANAGER,
            RealmRole.CONTRIBUTOR,
            RealmRole.READER,
        )
        self._check_realm_access(
            organization_id, realm_id, user_id, encryption_revision, can_read_roles
        )

    def _check_realm_write_access(self, organization_id, realm_id, user_id, encryption_revision):
        can_write_roles = (RealmRole.OWNER, RealmRole.MANAGER, RealmRole.CONTRIBUTOR)
        self._check_realm_access(
            organization_id, realm_id, user_id, encryption_revision, can_write_roles
        )

    def _check_realm_access(
        self,
        organization_id,
        realm_id,
        user_id,
        encryption_revision,
        allowed_roles,
        expected_maintenance=False,
    ):
        try:
            realm = self._realm_component._get_realm(organization_id, realm_id)
        except RealmNotFoundError:
            raise VlobNotFoundError(f"Realm `{realm_id}` doesn't exist")

        if realm.roles.get(user_id) not in allowed_roles:
            raise VlobAccessError()

        if expected_maintenance is False:
            if realm.status.in_maintenance:
                raise VlobInMaintenanceError(f"Realm `{realm_id}` is currently under maintenance")
        elif expected_maintenance is True:
            if not realm.status.in_maintenance:
                raise VlobNotInMaintenanceError(f"Realm `{realm_id}` not under maintenance")

        if encryption_revision not in (None, realm.status.encryption_revision):
            raise VlobEncryptionRevisionError()

    def _check_realm_in_maintenance_access(
        self, organization_id, realm_id, user_id, encryption_revision
    ):
        can_do_maintenance_roles = (RealmRole.OWNER,)
        self._check_realm_access(
            organization_id,
            realm_id,
            user_id,
            encryption_revision,
            can_do_maintenance_roles,
            expected_maintenance=True,
        )

    async def _update_changes(self, organization_id, author, realm_id, src_id, src_version=1):
        changes = retrieve_changes(organization_id, realm_id)
        changes.checkpoint += 1
        changes.changes[src_id] = (author, changes.checkpoint, src_version)
        key_changes = create_key_changes(organization_id, realm_id)
        broadcast_tx(key_changes, json.dumps(changes, cls=Encoder))

        await self._send_event(
            BackendEvent.REALM_VLOBS_UPDATED,
            organization_id=organization_id,
            author=author,
            realm_id=realm_id,
            checkpoint=changes.checkpoint,
            src_id=src_id,
            src_version=src_version,
        )

    async def create(
        self,
        organization_id: OrganizationID,
        author: DeviceID,
        realm_id: UUID,
        encryption_revision: int,
        vlob_id: UUID,
        timestamp: pendulum.DateTime,
        blob: bytes,
    ) -> None:
        self._check_realm_write_access(
            organization_id, realm_id, author.user_id, encryption_revision
        )

        if not set_vlob_keys_exists():
            broadcast_tx(create_key_set_vlob_keys(), json.dumps(VlobKeys(), cls=Encoder))

        if (organization_id, vlob_id) in retrieve_set_vlob_keys().data:
            raise VlobAlreadyExistsError()
        else:
            key_vlob = create_key_vlob(organization_id, vlob_id)
            broadcast_tx(key_vlob, json.dumps(Vlob(realm_id, [(blob, author, timestamp)]), cls=Encoder))
            set_vlob_keys = retrieve_set_vlob_keys()
            set_vlob_keys.data.append((organization_id, vlob_id))
            broadcast_tx(create_key_set_vlob_keys(), json.dumps(set_vlob_keys, cls=Encoder))
            await self._update_changes(organization_id, author, realm_id, vlob_id)

    async def read(
        self,
        organization_id: OrganizationID,
        author: DeviceID,
        encryption_revision: int,
        vlob_id: UUID,
        version: Optional[int] = None,
        timestamp: Optional[pendulum.DateTime] = None,
    ) -> Tuple[int, bytes, DeviceID, pendulum.DateTime]:
        vlob = get_vlob(organization_id, vlob_id)

        self._check_realm_read_access(
            organization_id, vlob.realm_id, author.user_id, encryption_revision
        )

        if version is None:
            if timestamp is None:
                version = vlob.current_version
            else:
                for i in range(vlob.current_version, 0, -1):
                    if vlob.data[i - 1][2] <= timestamp:
                        version = i
                        break
                else:
                    raise VlobVersionError()

        try:
            return (version, *vlob.data[version - 1])

        except IndexError:
            raise VlobVersionError()

    async def update(
        self,
        organization_id: OrganizationID,
        author: DeviceID,
        encryption_revision: int,
        vlob_id: UUID,
        version: int,
        timestamp: pendulum.DateTime,
        blob: bytes,
    ) -> None:
        vlob = get_vlob(organization_id, vlob_id)

        self._check_realm_write_access(
            organization_id, vlob.realm_id, author.user_id, encryption_revision
        )
        if version - 1 != vlob.current_version:
            raise VlobVersionError()
        if timestamp < vlob.data[vlob.current_version - 1][2]:
            raise VlobTimestampError(timestamp, vlob.data[vlob.current_version - 1][2])
        vlob.data.append((blob, author, timestamp))

        key_vlob = create_key_vlob(organization_id, vlob_id)
        value_vlob = json.dumps(vlob, cls=Encoder)
        broadcast_tx(key_vlob, value_vlob)
        await self._update_changes(organization_id, author, vlob.realm_id, vlob_id, version)

    async def poll_changes(
        self, organization_id: OrganizationID, author: DeviceID, realm_id: UUID, checkpoint: int
    ) -> Tuple[int, Dict[UUID, int]]:
        self._check_realm_read_access(organization_id, realm_id, author.user_id, None)

        changes = retrieve_changes(organization_id, realm_id)
        changes_since_checkpoint = {
            src_id: src_version
            for src_id, (_, change_checkpoint, src_version) in changes.changes.items()
            if change_checkpoint > checkpoint
        }
        return (changes.checkpoint, changes_since_checkpoint)

    async def list_versions(
        self, organization_id: OrganizationID, author: DeviceID, vlob_id: UUID
    ) -> Dict[int, Tuple[pendulum.DateTime, DeviceID]]:
        vlobs = get_vlob(organization_id, vlob_id)

        self._check_realm_read_access(organization_id, vlobs.realm_id, author.user_id, None)
        return {k: (v[2], v[1]) for (k, v) in enumerate(vlobs.data, 1)}

    async def maintenance_get_reencryption_batch(
        self,
        organization_id: OrganizationID,
        author: DeviceID,
        realm_id: UUID,
        encryption_revision: int,
        size: int,
    ) -> List[Tuple[UUID, int, bytes]]:
        self._check_realm_in_maintenance_access(
            organization_id, realm_id, author.user_id, encryption_revision
        )

        changes = retrieve_changes(organization_id, realm_id)
        assert changes.reencryption

        return changes.reencryption.get_batch(size)

    async def maintenance_save_reencryption_batch(
        self,
        organization_id: OrganizationID,
        author: DeviceID,
        realm_id: UUID,
        encryption_revision: int,
        batch: List[Tuple[UUID, int, bytes]],
    ) -> Tuple[int, int]:
        self._check_realm_in_maintenance_access(
            organization_id, realm_id, author.user_id, encryption_revision
        )

        changes = retrieve_changes(organization_id, realm_id)
        assert changes.reencryption

        total, done = changes.reencryption.save_batch(batch)

        return total, done



"""
To pass the test, we assume we have an empty database. Thus we need to remove transactions from Tendermint, which is something we can't do because this is a blockchain.
Instead we set all the previous transactions to a kind of "neutral status" to remove all information provided by those transactions
( we remove the information provide by transactions, not the transactions themselves).
WARNING: something still missing in the reset function because is we run the test twice, one more test failed in the second run.
"""
def reset_database():
    if set_vlob_keys_exists():
        vlob_keys = retrieve_set_vlob_keys()
        for k in vlob_keys.data:
            if vlob_exists(k[0], k[1]):
                vlob = get_vlob(k[0], k[1])
                broadcast_tx(create_key_vlob(k[0], k[1]), json.dumps(Vlob(vlob.realm_id), cls=Encoder))
        broadcast_tx(create_key_set_vlob_keys(), json.dumps(VlobKeys([]), cls=Encoder))

    if set_changes_keys_exists():
        changes_keys = retrieve_set_changes_keys()
        for k in changes_keys.data:
            if changes_exists(k[0], k[1]):
                broadcast_tx(create_key_changes(k[0], k[1]), json.dumps(Changes(), cls=Encoder))
        broadcast_tx(create_key_set_changes_keys(), json.dumps(ChangesKeys([]), cls=Encoder))


def get_vlob(organization_id, vlob_id):
    if vlob_exists(organization_id, vlob_id):
        return retrieve_vlob(organization_id, vlob_id)
    else:
        raise VlobNotFoundError(f"Vlob `{vlob_id}` doesn't exist")


def retrieve_tx(key):
    cmd = abci_addr + 'abci_query?data="' + key + '"'
    req = requests.get(cmd)
    raw_rep = req.json()
    raw_rep = base64.b64decode(raw_rep['result']['response']['value']).decode('utf-8')
    return raw_rep.replace('\'', '\"')


def broadcast_tx(key, value):
    cmd = abci_addr + 'broadcast_tx_commit?tx="Key%3F' + key + '%26Value%3F' + value.replace('\"', '\'') + '"'
    req = requests.get(cmd)


def vlob_exists(organization_id: OrganizationID, vlob_id: UUID):
    raw_rep = retrieve_tx(create_key_vlob(organization_id, vlob_id))
    return True if raw_rep != "0" else False


def changes_exists(organization_id: OrganizationID, realm_id: UUID):
    raw_rep = retrieve_tx(create_key_changes(organization_id, realm_id))
    return True if raw_rep != "0" else False


def set_vlob_keys_exists():
    raw_rep = retrieve_tx(create_key_set_vlob_keys())
    return True if raw_rep != "0" else False


def set_changes_keys_exists():
    raw_rep = retrieve_tx(create_key_set_changes_keys())
    return True if raw_rep != "0" else False


def create_key_vlob(organization_id: OrganizationID, vlob_id: UUID):
    return '(vlob, ' + organization_id.__str__() + ', ' + vlob_id.__str__() + ')'


def create_key_changes(organization_id: OrganizationID, realm_id: UUID):
    return '(changes, ' + organization_id.__str__() + ', ' + realm_id.__str__() + ')'


def create_key_set_vlob_keys():
    return '(vlob_keys)'


def create_key_set_changes_keys():
    return '(changes_keys)'


def retrieve_changes(organization_id: OrganizationID, realm_id: UUID):
    key = create_key_changes(organization_id, realm_id)
    if not set_changes_keys_exists():
        broadcast_tx(create_key_set_changes_keys(), json.dumps(ChangesKeys(), cls=Encoder))
    changes_keys = retrieve_set_changes_keys()
    if changes_exists(organization_id, realm_id):
        if not ((organization_id, realm_id)) in changes_keys.data:
            changes_keys.data.append((organization_id, realm_id))
            broadcast_tx(create_key_set_changes_keys(), json.dumps(changes_keys, cls=Encoder))
        raw_rep = retrieve_tx(key)
        return ChangesDecoder().decode(raw_rep, )
    else:
        changes_keys.data.append((organization_id, realm_id))
        broadcast_tx(create_key_set_changes_keys(), json.dumps(changes_keys, cls=Encoder))
        return Changes()


def retrieve_vlob(organization_id: OrganizationID, vlob_id: UUID):
    key = create_key_vlob(organization_id, vlob_id)
    raw_rep = retrieve_tx(key)
    return VlobDecoder().decode(raw_rep, )


def retrieve_set_vlob_keys():
    key = create_key_set_vlob_keys()
    raw_rep = retrieve_tx(key)
    return VlobKeysDecoder().decode(raw_rep, )


def retrieve_set_changes_keys():
    key = create_key_set_changes_keys()
    raw_rep = retrieve_tx(key)
    return ChangesKeysDecoder().decode(raw_rep, )
