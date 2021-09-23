import pytest
from uuid import UUID
from hashlib import sha256
from pendulum import now as pendulum_now
from uuid import uuid4

from tests.backend.common import realm_update_roles, vlob_create, vlob_read, vlob_update, vlob_history

from parsec.api.data import RealmRoleCertificateContent
from parsec.api.protocol import RealmRole
from parsec.api.protocol import DeviceID, OrganizationID
import pendulum

from unittest.mock import MagicMock

from parsec.backend.memory.vlob import (
    Vlob,
    Encoder,
    operations_per_epoch,
    retrieve_checkpoint,
    get_epoch,
    ServerOperation
)

from parsec.core.logged_core import CheckError

import json
from json import JSONEncoder, JSONDecoder
import base64

# Since checks protocol take place at the end f each epoch, tests run through few epochs which is number_epochs.
number_epochs = 4
assert number_epochs >= 1

epoch_to_attack = 1
assert epoch_to_attack >= 0
assert epoch_to_attack <= number_epochs - 1

# An enhancement : chose the client to attack. WARNING: This is not implemented in the unit test.
authors_to_attack = []

assert operations_per_epoch >= 0
assert operations_per_epoch % 2 == 0


class MockedBlockchain():
    data = {}

    def broadcast(self, k, v):
        self.data[k] = v

    def retrieve(self, k):
        return self.data.get(k, json.dumps({"checkpoints": []}))


@pytest.fixture
async def mocked_alice_backend_sock(monkeypatch, backend_sock_factory, backend, alice):
    mocked_bc = MockedBlockchain()
    monkeypatch.setattr("parsec.backend.memory.vlob.broadcast_tx", mocked_bc.broadcast)
    monkeypatch.setattr("parsec.backend.memory.vlob.retrieve_tx", mocked_bc.retrieve)
    async with backend_sock_factory(backend, alice) as sock:
        yield sock


@pytest.fixture
async def mocked_bob_backend_sock(monkeypatch, backend_sock_factory, backend, bob):
    mocked_bc = MockedBlockchain()
    monkeypatch.setattr("parsec.backend.memory.vlob.broadcast_tx", mocked_bc.broadcast)
    monkeypatch.setattr("parsec.backend.memory.vlob.retrieve_tx", mocked_bc.retrieve)
    async with backend_sock_factory(backend, bob) as sock:
        yield sock


@pytest.fixture
async def faulty_backend_signature(monkeypatch, backend):
    _update = backend.vlob.update
    starting_epoch = get_epoch()

    async def update(
        self,
        organization_id: OrganizationID,
        author: DeviceID,
        encryption_revision: int,
        vlob_id: UUID,
        version: int,
        timestamp: pendulum.DateTime,
        blob: bytes,
        signature: bytes,
    ) -> None:
        global epoch_to_attack
        from parsec.backend.memory.vlob import broadcast_tx, create_key_checkpoints

        _broadcast_tx = broadcast_tx
        broadcast_tx_mock = MagicMock()
        monkeypatch.setattr("parsec.backend.memory.vlob.broadcast_tx", broadcast_tx_mock)
        await _update(organization_id, author, encryption_revision, vlob_id, version, timestamp, blob, signature)
        if starting_epoch + epoch_to_attack == get_epoch() - 1:
            op_list = list(backend.vlob._vlobs.get((organization_id, vlob_id)).operations[-1].operation)
            op_list[5] = b"0"  # op_list[5] = signature
            backend.vlob._vlobs.get((organization_id, vlob_id)).operations[-1].operation = tuple(op_list)

        if broadcast_tx_mock.call_count:
            last_op = backend.vlob._vlobs.get((organization_id, vlob_id)).operations[
                backend.vlob._vlobs.get((organization_id, vlob_id)).current_operation - 1]
            list_checkpoints = retrieve_checkpoint(organization_id, vlob_id)
            list_checkpoints.checkpoints.append((get_epoch() - 1, sha256(
                bytes(json.dumps(last_op, cls=Encoder), encoding='utf-8')).hexdigest().__str__(), version))
            key = create_key_checkpoints(organization_id, vlob_id)
            value = json.dumps(list_checkpoints, cls=Encoder)
            _broadcast_tx(key, value)
        monkeypatch.setattr("parsec.backend.memory.vlob.broadcast_tx", _broadcast_tx)

    backend.vlob.update = update.__get__(backend)
    return backend


@pytest.fixture
async def faulty_backend_switch_operation(monkeypatch, backend):
    _update = backend.vlob.update
    starting_epoch = get_epoch()

    async def update(
        self,
        organization_id: OrganizationID,
        author: DeviceID,
        encryption_revision: int,
        vlob_id: UUID,
        version: int,
        timestamp: pendulum.DateTime,
        blob: bytes,
        signature: bytes,
    ) -> None:
        global epoch_to_attack
        from parsec.backend.memory.vlob import broadcast_tx, create_key_checkpoints

        _broadcast_tx = broadcast_tx
        broadcast_tx_mock = MagicMock()
        monkeypatch.setattr("parsec.backend.memory.vlob.broadcast_tx", broadcast_tx_mock)
        await _update(organization_id, author, encryption_revision, vlob_id, version, timestamp, blob, signature)

        if starting_epoch + epoch_to_attack == get_epoch() - 1:
            mem_prev_op = backend.vlob._vlobs.get((organization_id, vlob_id)).operations[-2].operation
            backend.vlob._vlobs.get((organization_id, vlob_id)).operations[-2].operation = \
                backend.vlob._vlobs.get((organization_id, vlob_id)).operations[-1].operation
            backend.vlob._vlobs.get((organization_id, vlob_id)).operations[-1].operation = mem_prev_op

            # switch previous hash
            prev_op_list = list(backend.vlob._vlobs.get((organization_id, vlob_id)).operations[-2].operation)
            next_op_list = list(backend.vlob._vlobs.get((organization_id, vlob_id)).operations[-1].operation)
            prev_op_list[4] = next_op_list[4]

            # in order to avoid hash chain error we need re-compute the hash
            op_to_hash = ServerOperation((prev_op_list[0], prev_op_list[1], prev_op_list[2], prev_op_list[3],
                                          prev_op_list[4], prev_op_list[5], prev_op_list[6]))
            hash_prev_op = sha256(bytes(json.dumps(op_to_hash, cls=Encoder), encoding='utf-8')).hexdigest().__str__()
            next_op_list[4] = hash_prev_op

            backend.vlob._vlobs.get((organization_id, vlob_id)).operations[-2].operation = tuple(prev_op_list)
            backend.vlob._vlobs.get((organization_id, vlob_id)).operations[-1].operation = tuple(next_op_list)
        if broadcast_tx_mock.call_count:
            last_op = backend.vlob._vlobs.get((organization_id, vlob_id)).operations[
                backend.vlob._vlobs.get((organization_id, vlob_id)).current_operation - 1]
            list_checkpoints = retrieve_checkpoint(organization_id, vlob_id)
            list_checkpoints.checkpoints.append((get_epoch() - 1, sha256(
                bytes(json.dumps(last_op, cls=Encoder), encoding='utf-8')).hexdigest().__str__(), version))
            key = create_key_checkpoints(organization_id, vlob_id)
            value = json.dumps(list_checkpoints, cls=Encoder)
            _broadcast_tx(key, value)
        monkeypatch.setattr("parsec.backend.memory.vlob.broadcast_tx", _broadcast_tx)

    backend.vlob.update = update.__get__(backend)
    return backend


@pytest.fixture
async def faulty_backend_hash_chain(monkeypatch, backend):
    _update = backend.vlob.update
    starting_epoch = get_epoch()

    async def update(
        self,
        organization_id: OrganizationID,
        author: DeviceID,
        encryption_revision: int,
        vlob_id: UUID,
        version: int,
        timestamp: pendulum.DateTime,
        blob: bytes,
        signature: bytes,
    ) -> None:
        global epoch_to_attack
        from parsec.backend.memory.vlob import broadcast_tx, create_key_checkpoints

        _broadcast_tx = broadcast_tx
        broadcast_tx_mock = MagicMock()
        monkeypatch.setattr("parsec.backend.memory.vlob.broadcast_tx", broadcast_tx_mock)
        await _update(organization_id, author, encryption_revision, vlob_id, version, timestamp, blob, signature)

        if starting_epoch + epoch_to_attack == get_epoch() - 1:
            op_list = list(backend.vlob._vlobs.get((organization_id, vlob_id)).operations[-1].operation)
            op_list[4] = "0"  # op_list[4] = hash prev digest
            backend.vlob._vlobs.get((organization_id, vlob_id)).operations[-1].operation = tuple(op_list)

        if broadcast_tx_mock.call_count:
            last_op = backend.vlob._vlobs.get((organization_id, vlob_id)).operations[
                backend.vlob._vlobs.get((organization_id, vlob_id)).current_operation - 1]
            list_checkpoints = retrieve_checkpoint(organization_id, vlob_id)
            list_checkpoints.checkpoints.append((get_epoch() - 1, sha256(
                bytes(json.dumps(last_op, cls=Encoder), encoding='utf-8')).hexdigest().__str__(), version))
            key = create_key_checkpoints(organization_id, vlob_id)
            value = json.dumps(list_checkpoints, cls=Encoder)
            _broadcast_tx(key, value)
        monkeypatch.setattr("parsec.backend.memory.vlob.broadcast_tx", _broadcast_tx)

    backend.vlob.update = update.__get__(backend)
    return backend


@pytest.fixture
async def faulty_backend_timestamp(monkeypatch, backend):
    _update = backend.vlob.update
    starting_epoch = get_epoch()

    async def update(
        self,
        organization_id: OrganizationID,
        author: DeviceID,
        encryption_revision: int,
        vlob_id: UUID,
        version: int,
        timestamp: pendulum.DateTime,
        blob: bytes,
        signature: bytes,
    ) -> None:
        global epoch_to_attack
        from parsec.backend.memory.vlob import broadcast_tx, create_key_checkpoints

        _broadcast_tx = broadcast_tx
        broadcast_tx_mock = MagicMock()
        monkeypatch.setattr("parsec.backend.memory.vlob.broadcast_tx", broadcast_tx_mock)
        await _update(organization_id, author, encryption_revision, vlob_id, version, timestamp, blob, signature)
        if starting_epoch + epoch_to_attack == get_epoch() - 1:
            op_list = list(backend.vlob._vlobs.get((organization_id, vlob_id)).operations[-1].operation)
            op_list[2] = op_list[2].add(seconds=1)
            backend.vlob._vlobs.get((organization_id, vlob_id)).operations[-1].operation = tuple(op_list)

        if broadcast_tx_mock.call_count:
            last_op = backend.vlob._vlobs.get((organization_id, vlob_id)).operations[
                backend.vlob._vlobs.get((organization_id, vlob_id)).current_operation - 1]
            list_checkpoints = retrieve_checkpoint(organization_id, vlob_id)
            list_checkpoints.checkpoints.append((get_epoch() - 1, sha256(
                bytes(json.dumps(last_op, cls=Encoder), encoding='utf-8')).hexdigest().__str__(), version))
            key = create_key_checkpoints(organization_id, vlob_id)
            value = json.dumps(list_checkpoints, cls=Encoder)
            _broadcast_tx(key, value)
        monkeypatch.setattr("parsec.backend.memory.vlob.broadcast_tx", _broadcast_tx)

    backend.vlob.update = update.__get__(backend)
    return backend


async def _realm_generate_certif_and_update_roles_or_fail(
    backend_sock, author, realm_id, user_id, role
):
    certif = RealmRoleCertificateContent(
        author=author.device_id,
        timestamp=pendulum_now(),
        realm_id=realm_id,
        user_id=user_id,
        role=role,
    ).dump_and_sign(author.signing_key)
    return await realm_update_roles(backend_sock, certif, check_rep=False)


def create_signature_write(user, vlob_id, encryption_revision, blob, timestamp, version) -> bytes:
    json_sig = {'ciphered': base64.b64encode(blob).decode('utf-8'),
                'encryption_revision': encryption_revision.__str__(), 'entry_id': vlob_id.__str__(),
                'timestamp': timestamp.__str__(), 'version': version.__str__()}
    return user.signing_key.sign(bytes(json.dumps(json_sig), encoding='utf-8'))


def create_signature_read(user, vlob_id, encryption_revision, timestamp, version) -> bytes:
    json_sig = {'encryption_revision': encryption_revision.__str__(), 'entry_id': vlob_id.__str__(),
                'timestamp': timestamp.__str__(), 'version': version.__str__()}
    return user.signing_key.sign(bytes(json.dumps(json_sig), encoding='utf-8'))


@pytest.mark.trio
async def test_retrieve_history_single_create_operation(alice, mocked_alice_backend_sock, realm):
    current_epoch = get_epoch()
    assert current_epoch >= 0

    history = []

    vlob_id = uuid4()
    blob = b"Initial commit."
    timestamp = pendulum_now()
    encryption_revision = 1
    vlob_reference_version = 1

    signature = create_signature_write(alice, vlob_id, encryption_revision, blob, timestamp, vlob_reference_version)

    rep = await vlob_create(mocked_alice_backend_sock, realm, vlob_id, timestamp=timestamp, blob=blob,
                            signature=signature)
    assert rep["status"] == "ok"
    vlob_reference_version += 1

    vlob_reference = Vlob(realm, [(blob, alice.device_id, timestamp)], [])
    hash_obj_after_operation = sha256(
        bytes(json.dumps(vlob_reference, cls=Encoder), encoding='utf-8')).hexdigest().__str__()

    history.append({"version": 1, "author": alice.device_id, "timestamp": timestamp,
                    "hash_obj_after_operation": hash_obj_after_operation, "hash_prev_digest": "0",
                    "signature": signature, "is_read_op": False})

    rep = await vlob_history(mocked_alice_backend_sock, vlob_id, after_version=1, before_version=1)

    assert rep == {"status": "ok", "history": history}


@pytest.mark.trio
async def test_retrieve_history_create_update_read_operation(alice, mocked_alice_backend_sock, realm):
    current_epoch = get_epoch()
    assert current_epoch >= 0

    history = []
    total_history = []

    vlob_id = uuid4()
    blob = b"Initial commit."
    timestamp = pendulum_now()
    encryption_revision = 1
    vlob_reference_version = 1
    vlob_backend_version = 1
    signature = create_signature_write(alice, vlob_id, encryption_revision, blob, timestamp, vlob_reference_version)

    vlob_reference = Vlob(realm, [(blob, alice.device_id, timestamp)], [])
    hash_obj_after_operation = sha256(
        bytes(json.dumps(vlob_reference, cls=Encoder), encoding='utf-8')).hexdigest().__str__()
    new_operation = ServerOperation(
        (vlob_reference_version, alice.device_id, timestamp, hash_obj_after_operation, "0", signature, False))
    vlob_reference.operations.append(new_operation)
    vlob_reference_version += 1
    vlob_backend_version += 1

    rep = await vlob_create(mocked_alice_backend_sock, realm, vlob_id, blob=blob, timestamp=timestamp,
                            signature=signature)
    assert rep["status"] == "ok"

    history.append({"version": 1, "author": alice.device_id, "timestamp": timestamp,
                    "hash_obj_after_operation": hash_obj_after_operation, "hash_prev_digest": "0",
                    "signature": signature, "is_read_op": False})
    total_history.append({"version": 1, "author": alice.device_id, "timestamp": timestamp,
                          "hash_obj_after_operation": hash_obj_after_operation, "hash_prev_digest": "0",
                          "signature": signature, "is_read_op": False})

    for epoch in range(number_epochs):
        # for the first history check (i.e. epoch = 0) we take into account the create op
        # so we manually set the after_version parameter to get the right history from the backend
        if epoch == 0:
            latest_safe_version_vlob_backend = 1
        else:
            latest_safe_version_vlob_backend = vlob_backend_version
        for i in range(2 * operations_per_epoch):

            timestamp = pendulum_now()
            if i % 2 == 0:

                # update reference vlob
                signature = create_signature_write(alice, vlob_id, encryption_revision, blob, timestamp,
                                                   vlob_reference_version)
                vlob_reference.data.append((blob, alice.device_id, timestamp))
                hash_obj_after_operation = sha256(
                    bytes(json.dumps(vlob_reference, cls=Encoder), encoding='utf-8')).hexdigest().__str__()
                hash_prev_digest = "0"
                if vlob_reference.current_operation != 0:
                    last_op = vlob_reference.operations[vlob_reference.current_operation - 1].operation
                    op_to_hash = ServerOperation(
                        (last_op[0], last_op[1], last_op[2], last_op[3], last_op[4], last_op[5], last_op[6]))
                    hash_prev_digest = sha256(
                        bytes(json.dumps(op_to_hash, cls=Encoder), encoding='utf-8')).hexdigest().__str__()
                new_operation = ServerOperation((vlob_reference_version, alice.device_id, timestamp,
                                                 hash_obj_after_operation, hash_prev_digest, signature, False))
                vlob_reference.operations.append(new_operation)
                history.append({"version": vlob_reference_version, "author": alice.device_id, "timestamp": timestamp,
                                "hash_obj_after_operation": hash_obj_after_operation,
                                "hash_prev_digest": hash_prev_digest, "signature": signature, "is_read_op": False})
                total_history.append(
                    {"version": vlob_reference_version, "author": alice.device_id, "timestamp": timestamp,
                     "hash_obj_after_operation": hash_obj_after_operation, "hash_prev_digest": hash_prev_digest,
                     "signature": signature, "is_read_op": False})
                vlob_reference_version += 1

                # update backend vlob
                rep = await vlob_update(mocked_alice_backend_sock, vlob_id, version=vlob_backend_version, blob=blob,
                                        encryption_revision=encryption_revision, timestamp=timestamp,
                                        signature=signature)
                assert rep["status"] == "ok"
                vlob_backend_version += 1
            else:
                # read reference vlob
                signature = create_signature_read(alice, vlob_id, encryption_revision, timestamp,
                                                  vlob_reference_version - 1)
                hash_obj_after_operation = sha256(
                    bytes(json.dumps(vlob_reference, cls=Encoder), encoding='utf-8')).hexdigest().__str__()
                hash_prev_digest = "0"
                if vlob_reference.current_operation != 0:
                    last_op = vlob_reference.operations[vlob_reference.current_operation - 1].operation
                    op_to_hash = ServerOperation(
                        (last_op[0], last_op[1], last_op[2], last_op[3], last_op[4], last_op[5], last_op[6]))
                    hash_prev_digest = sha256(
                        bytes(json.dumps(op_to_hash, cls=Encoder), encoding='utf-8')).hexdigest().__str__()
                new_operation = ServerOperation((vlob_reference_version - 1, alice.device_id, timestamp,
                                                 hash_obj_after_operation, hash_prev_digest, signature, True))
                vlob_reference.operations.append(new_operation)
                history.append(
                    {"version": vlob_reference_version - 1, "author": alice.device_id, "timestamp": timestamp,
                     "hash_obj_after_operation": hash_obj_after_operation, "hash_prev_digest": hash_prev_digest,
                     "signature": signature, "is_read_op": True})
                total_history.append(
                    {"version": vlob_reference_version - 1, "author": alice.device_id, "timestamp": timestamp,
                     "hash_obj_after_operation": hash_obj_after_operation, "hash_prev_digest": hash_prev_digest,
                     "signature": signature, "is_read_op": True})

                # read backend vlob
                rep = await vlob_read(mocked_alice_backend_sock, vlob_id, version=vlob_backend_version - 1,
                                      signature=signature, timestamp=timestamp)
                assert rep["status"] == "ok"

        # check history equality
        rep = await vlob_history(mocked_alice_backend_sock, vlob_id, after_version=latest_safe_version_vlob_backend,
                                 before_version=vlob_backend_version)
        # print(rep['history'])
        assert rep == {"status": "ok", "history": history}

        history = []

    # full history
    rep = await vlob_history(mocked_alice_backend_sock, vlob_id, after_version=1, before_version=vlob_backend_version)
    assert rep == {"status": "ok", "history": total_history}


@pytest.mark.trio
async def test_check_operations_alice(running_backend, alice, mocked_alice_backend_sock, alice_core, realm):
    current_epoch = get_epoch()
    assert current_epoch >= 0

    vlob_id = uuid4()
    vlob_reference = None
    encryption_revision = 1
    vlob_backend_version = 1
    vlob_reference_version = 1
    history = []

    for epoch in range(number_epochs):
        for i in range(operations_per_epoch):

            blob = bytes("Initial commit ", encoding='utf-8') + bytes(int(i + epoch * number_epochs).__str__(),
                                                                      encoding='utf-8') + bytes(".", encoding='utf-8')
            timestamp = pendulum_now()
            signature = create_signature_write(alice, vlob_id, encryption_revision, blob, timestamp,
                                               vlob_backend_version)
            # a = json.loads(alice.signing_key.verify_key.verify(signature).decode('utf_8'))['ciphered']
            # print(base64.decode(json.loads(alice.signing_key.verify_key.verify(signature).decode('utf_8'))['ciphered']).decode('utf-8'))
            # print(base64.b64decode(a).decode('utf-8'))
            if epoch == 0 and i == 0:
                # initialize vlob reference locally
                vlob_reference = Vlob(realm, [(blob, alice.device_id, timestamp)], [])
                hash_obj_after_operation = sha256(
                    bytes(json.dumps(vlob_reference, cls=Encoder), encoding='utf-8')).hexdigest().__str__()
                new_operation = ServerOperation((vlob_reference_version, alice.device_id, timestamp,
                                                 hash_obj_after_operation, "0", signature, False))
                vlob_reference.operations.append(new_operation)
                vlob_reference_version += 1

                # create vlob reference in the backend
                rep = await vlob_create(mocked_alice_backend_sock, realm, vlob_id, blob=blob, timestamp=timestamp,
                                        signature=signature)
                assert rep["status"] == "ok"

                if rep["status"] == "ok":
                    new_local_operation = (timestamp, alice.local_operation_storage.epoch, signature, False)
                    alice.local_operation_storage.add_op(vlob_id, vlob_backend_version, new_local_operation)
                    # the most current version is update after every operation
                    assert alice.local_operation_storage.storage.get(vlob_id)[3] == vlob_backend_version
                    vlob_backend_version += 1
            else:
                if i % 2 == 0:
                    # update data of reference vlob locally
                    vlob_reference.data.append((blob, alice.device_id, timestamp))
                    hash_obj_after_operation = sha256(
                        bytes(json.dumps(vlob_reference, cls=Encoder), encoding='utf-8')).hexdigest().__str__()
                    hash_prev_digest = "0"
                    if vlob_reference.current_operation != 0:
                        last_op = vlob_reference.operations[vlob_reference.current_operation - 1].operation
                        op_to_hash = ServerOperation(
                            (last_op[0], last_op[1], last_op[2], last_op[3], last_op[4], last_op[5], last_op[6]))
                        hash_prev_digest = sha256(
                            bytes(json.dumps(op_to_hash, cls=Encoder), encoding='utf-8')).hexdigest().__str__()
                    new_operation = ServerOperation((vlob_reference_version, alice.device_id, timestamp,
                                                     hash_obj_after_operation, hash_prev_digest, signature, False))
                    vlob_reference.operations.append(new_operation)
                    history.append(
                        {"version": vlob_reference_version, "author": alice.device_id, "timestamp": timestamp,
                         "hash_obj_after_operation": hash_obj_after_operation, "hash_prev_digest": hash_prev_digest,
                         "signature": signature, "is_read_op": False})
                    vlob_reference_version += 1

                    # update vlob data in the backend
                    rep = await vlob_update(mocked_alice_backend_sock, vlob_id, encryption_revision=encryption_revision,
                                            version=vlob_backend_version, blob=blob, timestamp=timestamp,
                                            signature=signature)
                    assert rep["status"] == "ok"

                    if rep["status"] == "ok":
                        new_local_operation = (timestamp, alice.local_operation_storage.epoch, signature, False)
                        alice.local_operation_storage.add_op(vlob_id, vlob_backend_version, new_local_operation)
                        # the most current version is update after every operation
                        assert alice.local_operation_storage.storage.get(vlob_id)[3] == vlob_backend_version
                        vlob_backend_version += 1
                else:
                    # read operation, so we update the expected content to be read
                    blob = bytes("Initial commit ", encoding='utf-8') + bytes(
                        int(i - 1 + epoch * number_epochs).__str__(), encoding='utf-8') + bytes(".", encoding='utf-8')
                    signature = create_signature_read(alice, vlob_id, encryption_revision, timestamp,
                                                      vlob_reference_version - 1)
                    hash_obj_after_operation = sha256(
                        bytes(json.dumps(vlob_reference, cls=Encoder), encoding='utf-8')).hexdigest().__str__()
                    hash_prev_digest = "0"
                    if vlob_reference.current_operation != 0:
                        last_op = vlob_reference.operations[vlob_reference.current_operation - 1].operation
                        op_to_hash = ServerOperation(
                            (last_op[0], last_op[1], last_op[2], last_op[3], last_op[4], last_op[5], last_op[6]))
                        hash_prev_digest = sha256(
                            bytes(json.dumps(op_to_hash, cls=Encoder), encoding='utf-8')).hexdigest().__str__()
                    new_operation = ServerOperation((vlob_reference_version - 1, alice.device_id, timestamp,
                                                     hash_obj_after_operation, hash_prev_digest, signature, True))
                    vlob_reference.operations.append(new_operation)
                    history.append(
                        {"version": vlob_reference_version - 1, "author": alice.device_id, "timestamp": timestamp,
                         "hash_obj_after_operation": hash_obj_after_operation, "hash_prev_digest": hash_prev_digest,
                         "signature": signature, "is_read_op": True})

                    # update vlob data in the backend
                    rep = await vlob_read(mocked_alice_backend_sock, vlob_id, version=vlob_backend_version - 1,
                                          signature=signature, timestamp=timestamp)
                    assert rep["status"] == "ok"

                    if rep["status"] == "ok":
                        new_local_operation = (timestamp, alice.local_operation_storage.epoch, signature, True)
                        alice.local_operation_storage.add_op(vlob_id, vlob_backend_version - 1, new_local_operation)
                        # the most current version is update after every operation
                        assert alice.local_operation_storage.storage.get(vlob_id)[3] == vlob_backend_version - 1
                        val_list = list(alice.local_operation_storage.storage[vlob_id])
                        # print(rep['blob'])
                        val_list[6].append((rep['version'], base64.b64encode(rep['blob']).decode('utf-8')))
                        alice.local_operation_storage.storage[vlob_id] = tuple(val_list)
        assert (await alice_core.check_operations_epoch(after_epoch=alice.local_operation_storage.epoch,
                                                        before_epoch=alice.local_operation_storage.epoch))[
                   0] == CheckError.NO_ERROR
        assert alice.local_operation_storage.storage.get(vlob_id)[1] == []

        # safe version and current version are equal (since every check has been passed)
        assert alice.local_operation_storage.storage.get(vlob_id)[2] == \
               alice.local_operation_storage.storage.get(vlob_id)[3]
        assert alice.local_operation_storage.storage.get(vlob_id)[3] == vlob_backend_version - 1

        last_digest_vlob_reference = history[len(history) - 1]
        op_to_hash = ServerOperation((last_digest_vlob_reference['version'], last_digest_vlob_reference['author'],
                                      last_digest_vlob_reference['timestamp'],
                                      last_digest_vlob_reference['hash_obj_after_operation'],
                                      last_digest_vlob_reference['hash_prev_digest'],
                                      last_digest_vlob_reference['signature'],
                                      last_digest_vlob_reference['is_read_op']))
        hash_last_op = sha256(bytes(json.dumps(op_to_hash, cls=Encoder), encoding='utf-8')).hexdigest().__str__()

        assert alice.local_operation_storage.storage.get(vlob_id)[4] == sha256(
            bytes(json.dumps(op_to_hash, cls=Encoder), encoding='utf-8')).hexdigest().__str__()

        assert alice.local_operation_storage.storage[vlob_id][5] == False


@pytest.mark.trio
async def test_check_operations_same_epoch_alice_and_bob(running_backend, alice, bob, mocked_alice_backend_sock,
                                                         mocked_bob_backend_sock, alice_core, bob_core, realm, backend):
    assert get_epoch() >= 0

    vlob_id = uuid4()

    rep = await _realm_generate_certif_and_update_roles_or_fail(mocked_alice_backend_sock, alice, realm, bob.user_id,
                                                                RealmRole.CONTRIBUTOR)
    assert rep["status"] == "ok"

    encryption_revision = 1
    vlob_backend_version = 1
    for epoch in range(number_epochs):
        for i in range(operations_per_epoch):
            blob = b"Initial commit " + bytes([i + epoch * number_epochs]) + b"."
            timestamp = pendulum_now()
            signature = create_signature_write(alice, vlob_id, encryption_revision, blob, timestamp,
                                               vlob_backend_version)

            if epoch == 0 and i == 0:
                rep = await vlob_create(mocked_alice_backend_sock, realm, vlob_id, blob=blob, timestamp=timestamp,
                                        signature=signature)
                assert rep["status"] == "ok"

                if rep["status"] == "ok":
                    new_local_operation = (timestamp, alice.local_operation_storage.epoch, signature, False)
                    alice.local_operation_storage.add_op(vlob_id, vlob_backend_version, new_local_operation)
                    # the most current version is update after every operation
                    assert alice.local_operation_storage.storage.get(vlob_id)[3] == vlob_backend_version
                    vlob_backend_version += 1
            else:
                if i % 2 == 0:
                    rep = await vlob_update(mocked_alice_backend_sock, vlob_id, encryption_revision=encryption_revision,
                                            version=vlob_backend_version, blob=blob, timestamp=timestamp,
                                            signature=signature)
                    assert rep["status"] == "ok"

                    if rep["status"] == "ok":
                        new_local_operation = (timestamp, alice.local_operation_storage.epoch, signature, False)
                        alice.local_operation_storage.add_op(vlob_id, vlob_backend_version, new_local_operation)
                        # the most current version is update after every operation
                        assert alice.local_operation_storage.storage.get(vlob_id)[3] == vlob_backend_version
                        vlob_backend_version += 1
                else:
                    blob = b"Initial commit " + bytes([i - 1 + epoch * number_epochs]) + b"."
                    signature = create_signature_read(bob, vlob_id, encryption_revision, timestamp,
                                                      vlob_backend_version - 1)

                    rep = await vlob_read(mocked_bob_backend_sock, vlob_id, version=vlob_backend_version - 1,
                                          signature=signature, timestamp=timestamp)
                    assert rep["status"] == "ok"

                    if rep["status"] == "ok":
                        new_local_operation = (timestamp, bob.local_operation_storage.epoch, signature, True)
                        bob.local_operation_storage.add_op(vlob_id, vlob_backend_version - 1, new_local_operation)
                        # the most current version is update after every operation
                        assert bob.local_operation_storage.storage.get(vlob_id)[3] == vlob_backend_version - 1
                        val_list = list(bob.local_operation_storage.storage[vlob_id])
                        val_list[6].append((rep['version'], base64.b64encode(rep['blob']).decode('utf-8')))
                        bob.local_operation_storage.storage[vlob_id] = tuple(val_list)

        assert (await alice_core.check_operations_epoch(after_epoch=alice.local_operation_storage.epoch,
                                                        before_epoch=alice.local_operation_storage.epoch))[
                   0] == CheckError.NO_ERROR
        assert (await bob_core.check_operations_epoch(after_epoch=bob.local_operation_storage.epoch,
                                                      before_epoch=bob.local_operation_storage.epoch))[
                   0] == CheckError.NO_ERROR


@pytest.mark.trio
async def test_check_operations_different_epoch_alice_and_bob(running_backend, alice, bob, mocked_alice_backend_sock,
                                                              mocked_bob_backend_sock, alice_core, bob_core, realm,
                                                              backend):
    assert get_epoch() >= 0

    vlob_id = uuid4()

    rep = await _realm_generate_certif_and_update_roles_or_fail(mocked_alice_backend_sock, alice, realm, bob.user_id,
                                                                RealmRole.CONTRIBUTOR)
    assert rep["status"] == "ok"

    encryption_revision = 1
    vlob_backend_version = 1
    for epoch in range(number_epochs):
        for i in range(operations_per_epoch):
            timestamp = pendulum_now()
            blob = b"Initial commit " + bytes([i + epoch * number_epochs]) + b" alice"
            signature = create_signature_write(alice, vlob_id, encryption_revision, blob, timestamp,
                                               vlob_backend_version)

            if epoch == 0 and i == 0:
                rep = await vlob_create(mocked_alice_backend_sock, realm, vlob_id, blob=blob, timestamp=timestamp,
                                        signature=signature)
                assert rep["status"] == "ok"

                if rep["status"] == "ok":
                    new_local_operation = (timestamp, alice.local_operation_storage.epoch, signature)
                    alice.local_operation_storage.add_op(vlob_id, vlob_backend_version, new_local_operation)
                    vlob_backend_version += 1
            else:
                rep = await vlob_update(mocked_alice_backend_sock, vlob_id, encryption_revision=encryption_revision,
                                        version=vlob_backend_version, blob=blob, timestamp=timestamp,
                                        signature=signature)
                assert rep["status"] == "ok"

                if rep["status"] == "ok":
                    new_local_operation = (timestamp, alice.local_operation_storage.epoch, signature)
                    alice.local_operation_storage.add_op(vlob_id, vlob_backend_version, new_local_operation)
                    vlob_backend_version += 1

        assert (await alice_core.check_operations_epoch(after_epoch=alice.local_operation_storage.epoch,
                                                        before_epoch=alice.local_operation_storage.epoch))[
                   0] == CheckError.NO_ERROR
        assert (await bob_core.check_operations_epoch(after_epoch=bob.local_operation_storage.epoch,
                                                      before_epoch=bob.local_operation_storage.epoch))[
                   0] == CheckError.NO_ERROR

        for i in range(operations_per_epoch):
            timestamp = pendulum_now()
            blob = b"Initial commit " + bytes([i + epoch * number_epochs]) + b" bob"
            signature = create_signature_write(bob, vlob_id, encryption_revision, blob, timestamp, vlob_backend_version)

            rep = await vlob_update(mocked_bob_backend_sock, vlob_id, encryption_revision=encryption_revision,
                                    version=vlob_backend_version, blob=blob, timestamp=timestamp, signature=signature)
            assert rep["status"] == "ok"

            if rep["status"] == "ok":
                new_local_operation = (timestamp, bob.local_operation_storage.epoch, signature)
                bob.local_operation_storage.add_op(vlob_id, vlob_backend_version, new_local_operation)
                vlob_backend_version += 1

        assert (await alice_core.check_operations_epoch(after_epoch=alice.local_operation_storage.epoch,
                                                        before_epoch=alice.local_operation_storage.epoch))[
                   0] == CheckError.NO_ERROR
        assert (await bob_core.check_operations_epoch(after_epoch=bob.local_operation_storage.epoch,
                                                      before_epoch=bob.local_operation_storage.epoch))[
                   0] == CheckError.NO_ERROR


@pytest.mark.trio
async def test_equality_hash_latest_digest_from_history_and_from_blockchain(alice, mocked_alice_backend_sock, realm):
    current_epoch = get_epoch()
    assert current_epoch >= 0

    vlob_id = uuid4()

    encryption_revision = 1
    vlob_backend_version = 1

    for epoch in range(number_epochs):
        latest_safe_version_vlob_backend = vlob_backend_version

        for i in range(operations_per_epoch):
            timestamp = pendulum_now()
            blob = b"Initial commit " + bytes([i + epoch * number_epochs]) + b" alice"
            signature = create_signature_write(alice, vlob_id, encryption_revision, blob, timestamp,
                                               vlob_backend_version)

            if epoch == 0 and i == 0:
                rep = await vlob_create(mocked_alice_backend_sock, realm, vlob_id, blob=blob, timestamp=timestamp,
                                        signature=signature)
                assert rep["status"] == "ok"
                vlob_backend_version += 1
            else:
                rep = await vlob_update(mocked_alice_backend_sock, vlob_id, version=vlob_backend_version,
                                        encryption_revision=encryption_revision, blob=blob, timestamp=timestamp,
                                        signature=signature)
                assert rep["status"] == "ok"
                vlob_backend_version += 1

        rep = await vlob_history(mocked_alice_backend_sock, vlob_id, after_version=latest_safe_version_vlob_backend,
                                 before_version=vlob_backend_version)
        assert rep["status"] == "ok"

        checkpoints_list = retrieve_checkpoint(alice.organization_id, vlob_id)

        last_op = rep['history'][len(rep['history']) - 1]
        op_to_hash = ServerOperation((last_op['version'], last_op['author'], last_op['timestamp'],
                                      last_op['hash_obj_after_operation'], last_op['hash_prev_digest'],
                                      last_op['signature'], last_op['is_read_op']))

        assert checkpoints_list.checkpoints[epoch][0] == current_epoch + epoch
        assert checkpoints_list.checkpoints[epoch][1] == sha256(
            bytes(json.dumps(op_to_hash, cls=Encoder), encoding='utf-8')).hexdigest().__str__()
        assert checkpoints_list.checkpoints[epoch][2] == vlob_backend_version - 1


@pytest.mark.trio
async def test_invalid_signature_error_alice_and_bob_faulty_backend(running_backend, alice, bob,
                                                                    mocked_alice_backend_sock, mocked_bob_backend_sock,
                                                                    alice_core, bob_core, realm,
                                                                    faulty_backend_signature):
    global epoch_to_attack
    assert get_epoch() >= 0

    vlob_id = uuid4()
    blob = b"Initial commit."
    timestamp = pendulum_now()

    rep = await _realm_generate_certif_and_update_roles_or_fail(mocked_alice_backend_sock, alice, realm, bob.user_id,
                                                                RealmRole.CONTRIBUTOR)
    assert rep["status"] == "ok"

    encryption_revision = 1
    vlob_backend_version = 1
    cnt = 0

    for epoch in range(number_epochs):
        for i in range(operations_per_epoch):
            if i % 2 == 0:
                timestamp = pendulum_now()
                blob = b"Initial commit " + bytes([i + epoch * number_epochs]) + b" alice"
                signature = create_signature_write(alice, vlob_id, encryption_revision, blob, timestamp,
                                                   vlob_backend_version)

                if epoch == 0 and i == 0:
                    rep = await vlob_create(mocked_alice_backend_sock, realm, vlob_id, blob=blob, timestamp=timestamp,
                                            signature=signature)
                    assert rep["status"] == "ok"

                    if rep["status"] == "ok":
                        new_local_operation = (timestamp, alice.local_operation_storage.epoch, signature)
                        alice.local_operation_storage.add_op(vlob_id, vlob_backend_version, new_local_operation)
                        vlob_backend_version += 1
                        cnt += 1
                else:
                    rep = await vlob_update(mocked_alice_backend_sock, vlob_id, encryption_revision=encryption_revision,
                                            version=vlob_backend_version, blob=blob, timestamp=timestamp,
                                            signature=signature)
                    assert rep["status"] == "ok"

                    if rep["status"] == "ok":
                        new_local_operation = (timestamp, alice.local_operation_storage.epoch, signature)
                        alice.local_operation_storage.add_op(vlob_id, vlob_backend_version, new_local_operation)
                        vlob_backend_version += 1
                        cnt += 1
            else:
                timestamp = pendulum_now()
                blob = b"Initial commit " + bytes([i + epoch * number_epochs]) + b" bob"
                signature = create_signature_write(bob, vlob_id, encryption_revision, blob, timestamp,
                                                   vlob_backend_version)

                rep = await vlob_update(mocked_bob_backend_sock, vlob_id, encryption_revision=encryption_revision,
                                        version=vlob_backend_version, blob=blob, timestamp=timestamp,
                                        signature=signature)
                assert rep["status"] == "ok"

                if rep["status"] == "ok":
                    new_local_operation = (timestamp, bob.local_operation_storage.epoch, signature)
                    bob.local_operation_storage.add_op(vlob_id, vlob_backend_version, new_local_operation)
                    vlob_backend_version += 1
                    cnt += 1
        if epoch >= epoch_to_attack:
            assert (await alice_core.check_operations_epoch(after_epoch=alice.local_operation_storage.epoch,
                                                            before_epoch=alice.local_operation_storage.epoch))[
                       0] == CheckError.SIGNATURE_VALIDITY_ERROR
            assert (await alice_core.check_operations_epoch(after_epoch=alice.local_operation_storage.epoch,
                                                            before_epoch=alice.local_operation_storage.epoch))[
                       1] == vlob_id
            assert alice.local_operation_storage.storage[vlob_id][5] == True
            assert (await bob_core.check_operations_epoch(after_epoch=bob.local_operation_storage.epoch,
                                                          before_epoch=bob.local_operation_storage.epoch))[
                       0] == CheckError.SIGNATURE_VALIDITY_ERROR
            assert (await bob_core.check_operations_epoch(after_epoch=alice.local_operation_storage.epoch,
                                                          before_epoch=alice.local_operation_storage.epoch))[
                       1] == vlob_id
            assert bob.local_operation_storage.storage[vlob_id][5] == True
        if epoch < epoch_to_attack:
            assert (await alice_core.check_operations_epoch(after_epoch=alice.local_operation_storage.epoch,
                                                            before_epoch=alice.local_operation_storage.epoch))[
                       0] == CheckError.NO_ERROR
            assert (await bob_core.check_operations_epoch(after_epoch=bob.local_operation_storage.epoch,
                                                          before_epoch=bob.local_operation_storage.epoch))[
                       0] == CheckError.NO_ERROR


@pytest.mark.trio
async def test_switch_operation_error_alice_and_bob_faulty_backend(running_backend, alice, bob,
                                                                   mocked_alice_backend_sock, mocked_bob_backend_sock,
                                                                   alice_core, bob_core, realm,
                                                                   faulty_backend_switch_operation):
    global epoch_to_attack
    assert get_epoch() >= 0

    vlob_id = uuid4()

    assert epoch_to_attack >= 0

    rep = await _realm_generate_certif_and_update_roles_or_fail(mocked_alice_backend_sock, alice, realm, bob.user_id,
                                                                RealmRole.CONTRIBUTOR)
    assert rep["status"] == "ok"

    encryption_revision = 1
    vlob_backend_version = 1
    cnt = 0

    for epoch in range(number_epochs):
        for i in range(operations_per_epoch):

            if i % 2 == 0:
                timestamp = pendulum_now()
                blob = b"Initial commit " + bytes([i + epoch * number_epochs]) + b" alice"
                signature = create_signature_write(alice, vlob_id, encryption_revision, blob, timestamp,
                                                   vlob_backend_version)

                if epoch == 0 and i == 0:
                    rep = await vlob_create(mocked_alice_backend_sock, realm, vlob_id, blob=blob, timestamp=timestamp,
                                            signature=signature)
                    assert rep["status"] == "ok"

                    if rep["status"] == "ok":
                        new_local_operation = (timestamp, alice.local_operation_storage.epoch, signature)
                        alice.local_operation_storage.add_op(vlob_id, vlob_backend_version, new_local_operation)
                        vlob_backend_version += 1
                        cnt += 1
                else:
                    rep = await vlob_update(mocked_alice_backend_sock, vlob_id, encryption_revision=encryption_revision,
                                            version=vlob_backend_version, blob=blob, timestamp=timestamp,
                                            signature=signature)
                    assert rep["status"] == "ok"

                    if rep["status"] == "ok":
                        new_local_operation = (timestamp, alice.local_operation_storage.epoch, signature)
                        alice.local_operation_storage.add_op(vlob_id, vlob_backend_version, new_local_operation)
                        vlob_backend_version += 1
                        cnt += 1
            else:
                timestamp = pendulum_now()
                blob = b"Initial commit " + bytes([i + epoch * number_epochs]) + b" bob"
                signature = create_signature_write(bob, vlob_id, encryption_revision, blob, timestamp,
                                                   vlob_backend_version)

                rep = await vlob_update(mocked_bob_backend_sock, vlob_id, encryption_revision=encryption_revision,
                                        version=vlob_backend_version, blob=blob, timestamp=timestamp,
                                        signature=signature)
                assert rep["status"] == "ok"

                if rep["status"] == "ok":
                    new_local_operation = (timestamp, bob.local_operation_storage.epoch, signature)
                    bob.local_operation_storage.add_op(vlob_id, vlob_backend_version, new_local_operation)
                    vlob_backend_version += 1
                    cnt += 1
        if epoch >= epoch_to_attack:
            assert (await alice_core.check_operations_epoch(after_epoch=alice.local_operation_storage.epoch,
                                                            before_epoch=alice.local_operation_storage.epoch))[
                       0] == CheckError.SWITCH_OPERATION_ERROR
            assert (await alice_core.check_operations_epoch(after_epoch=alice.local_operation_storage.epoch,
                                                            before_epoch=alice.local_operation_storage.epoch))[
                       1] == vlob_id
            assert alice.local_operation_storage.storage[vlob_id][5] == True
            assert (await bob_core.check_operations_epoch(after_epoch=bob.local_operation_storage.epoch,
                                                          before_epoch=bob.local_operation_storage.epoch))[
                       0] == CheckError.SWITCH_OPERATION_ERROR
            assert (await bob_core.check_operations_epoch(after_epoch=alice.local_operation_storage.epoch,
                                                          before_epoch=alice.local_operation_storage.epoch))[
                       1] == vlob_id
            assert bob.local_operation_storage.storage[vlob_id][5] == True
        if epoch < epoch_to_attack:
            assert (await alice_core.check_operations_epoch(after_epoch=alice.local_operation_storage.epoch,
                                                            before_epoch=alice.local_operation_storage.epoch))[
                       0] == CheckError.NO_ERROR
            assert (await bob_core.check_operations_epoch(after_epoch=bob.local_operation_storage.epoch,
                                                          before_epoch=bob.local_operation_storage.epoch))[
                       0] == CheckError.NO_ERROR


@pytest.mark.trio
async def test_hash_chain_error_alice_and_bob_faulty_backend(running_backend, alice, bob, mocked_alice_backend_sock,
                                                             mocked_bob_backend_sock, alice_core, bob_core, realm,
                                                             faulty_backend_hash_chain):
    global epoch_to_attack
    assert get_epoch() >= 0

    vlob_id = uuid4()

    rep = await _realm_generate_certif_and_update_roles_or_fail(mocked_alice_backend_sock, alice, realm, bob.user_id,
                                                                RealmRole.CONTRIBUTOR)
    assert rep["status"] == "ok"

    encryption_revision = 1
    vlob_backend_version = 1
    cnt = 0

    for epoch in range(number_epochs):
        for i in range(operations_per_epoch):

            if i % 2 == 0:
                timestamp = pendulum_now()
                blob = b"Initial commit " + bytes([i + epoch * number_epochs]) + b" alice"
                signature = create_signature_write(alice, vlob_id, encryption_revision, blob, timestamp,
                                                   vlob_backend_version)

                if epoch == 0 and i == 0:
                    rep = await vlob_create(mocked_alice_backend_sock, realm, vlob_id, blob=blob, timestamp=timestamp,
                                            signature=signature)
                    assert rep["status"] == "ok"

                    if rep["status"] == "ok":
                        new_local_operation = (timestamp, alice.local_operation_storage.epoch, signature)
                        alice.local_operation_storage.add_op(vlob_id, vlob_backend_version, new_local_operation)
                        vlob_backend_version += 1
                        cnt += 1
                else:
                    rep = await vlob_update(mocked_alice_backend_sock, vlob_id, encryption_revision=encryption_revision,
                                            version=vlob_backend_version, blob=blob, timestamp=timestamp,
                                            signature=signature)
                    assert rep["status"] == "ok"

                    if rep["status"] == "ok":
                        new_local_operation = (timestamp, alice.local_operation_storage.epoch, signature)
                        alice.local_operation_storage.add_op(vlob_id, vlob_backend_version, new_local_operation)
                        vlob_backend_version += 1
                        cnt += 1
            else:
                timestamp = pendulum_now()
                blob = b"Initial commit " + bytes([i + epoch * number_epochs]) + b" bob"
                signature = create_signature_write(bob, vlob_id, encryption_revision, blob, timestamp,
                                                   vlob_backend_version)

                rep = await vlob_update(mocked_bob_backend_sock, vlob_id, encryption_revision=encryption_revision,
                                        version=vlob_backend_version, blob=blob, timestamp=timestamp,
                                        signature=signature)
                assert rep["status"] == "ok"

                if rep["status"] == "ok":
                    new_local_operation = (timestamp, bob.local_operation_storage.epoch, signature)
                    bob.local_operation_storage.add_op(vlob_id, vlob_backend_version, new_local_operation)
                    vlob_backend_version += 1
                    cnt += 1

        if epoch >= epoch_to_attack:
            assert (await alice_core.check_operations_epoch(after_epoch=alice.local_operation_storage.epoch,
                                                            before_epoch=alice.local_operation_storage.epoch))[
                       0] == CheckError.HASH_CHAIN_ERROR
            assert (await alice_core.check_operations_epoch(after_epoch=alice.local_operation_storage.epoch,
                                                            before_epoch=alice.local_operation_storage.epoch))[
                       1] == vlob_id
            assert alice.local_operation_storage.storage[vlob_id][5] == True
            assert (await bob_core.check_operations_epoch(after_epoch=bob.local_operation_storage.epoch,
                                                          before_epoch=bob.local_operation_storage.epoch))[
                       0] == CheckError.HASH_CHAIN_ERROR
            assert (await bob_core.check_operations_epoch(after_epoch=alice.local_operation_storage.epoch,
                                                          before_epoch=alice.local_operation_storage.epoch))[
                       1] == vlob_id
            assert bob.local_operation_storage.storage[vlob_id][5] == True
        if epoch < epoch_to_attack:
            assert (await alice_core.check_operations_epoch(after_epoch=alice.local_operation_storage.epoch,
                                                            before_epoch=alice.local_operation_storage.epoch))[
                       0] == CheckError.NO_ERROR
            assert (await bob_core.check_operations_epoch(after_epoch=bob.local_operation_storage.epoch,
                                                          before_epoch=bob.local_operation_storage.epoch))[
                       0] == CheckError.NO_ERROR


@pytest.mark.trio
async def test_check_timestamp_error_alice_and_bob_faulty_backend(running_backend, alice, bob,
                                                                  mocked_alice_backend_sock, mocked_bob_backend_sock,
                                                                  alice_core, bob_core, realm,
                                                                  faulty_backend_timestamp):
    global epoch_to_attack
    assert get_epoch() >= 0

    vlob_id = uuid4()

    rep = await _realm_generate_certif_and_update_roles_or_fail(mocked_alice_backend_sock, alice, realm, bob.user_id,
                                                                RealmRole.CONTRIBUTOR)
    assert rep["status"] == "ok"

    encryption_revision = 1
    vlob_backend_version = 1

    for epoch in range(number_epochs):
        for i in range(operations_per_epoch):

            if i % 2 == 0:
                timestamp = pendulum_now()
                blob = b"Initial commit " + bytes([i + epoch * number_epochs]) + b" alice"
                signature = create_signature_write(alice, vlob_id, encryption_revision, blob, timestamp,
                                                   vlob_backend_version)

                if epoch == 0 and i == 0:
                    rep = await vlob_create(mocked_alice_backend_sock, realm, vlob_id, blob=blob, timestamp=timestamp,
                                            signature=signature)
                    assert rep["status"] == "ok"

                    if rep["status"] == "ok":
                        new_local_operation = (timestamp, alice.local_operation_storage.epoch, signature)
                        alice.local_operation_storage.add_op(vlob_id, vlob_backend_version, new_local_operation)
                        vlob_backend_version += 1
                else:
                    rep = await vlob_update(mocked_alice_backend_sock, vlob_id, encryption_revision=encryption_revision,
                                            version=vlob_backend_version, blob=blob, timestamp=timestamp,
                                            signature=signature)
                    assert rep["status"] == "ok"

                    if rep["status"] == "ok":
                        new_local_operation = (timestamp, alice.local_operation_storage.epoch, signature)
                        alice.local_operation_storage.add_op(vlob_id, vlob_backend_version, new_local_operation)
                        vlob_backend_version += 1
            else:
                timestamp = pendulum_now()
                blob = b"Initial commit " + bytes([i + epoch * number_epochs]) + b" bob"
                signature = create_signature_write(bob, vlob_id, encryption_revision, blob, timestamp,
                                                   vlob_backend_version)

                rep = await vlob_update(mocked_bob_backend_sock, vlob_id, encryption_revision=encryption_revision,
                                        version=vlob_backend_version, blob=blob, timestamp=timestamp,
                                        signature=signature)
                assert rep["status"] == "ok"

                if rep["status"] == "ok":
                    new_local_operation = (timestamp, bob.local_operation_storage.epoch, signature)
                    bob.local_operation_storage.add_op(vlob_id, vlob_backend_version, new_local_operation)
                    vlob_backend_version += 1
        if epoch >= epoch_to_attack:
            assert (await alice_core.check_operations_epoch(after_epoch=alice.local_operation_storage.epoch,
                                                            before_epoch=alice.local_operation_storage.epoch))[
                       0] == CheckError.TIMESTAMP_VALIDITY_ERROR
            assert (await alice_core.check_operations_epoch(after_epoch=alice.local_operation_storage.epoch,
                                                            before_epoch=alice.local_operation_storage.epoch))[
                       1] == vlob_id
            assert alice.local_operation_storage.storage[vlob_id][5] == True
            assert (await bob_core.check_operations_epoch(after_epoch=bob.local_operation_storage.epoch,
                                                          before_epoch=bob.local_operation_storage.epoch))[
                       0] == CheckError.TIMESTAMP_VALIDITY_ERROR
            assert (await bob_core.check_operations_epoch(after_epoch=alice.local_operation_storage.epoch,
                                                          before_epoch=alice.local_operation_storage.epoch))[
                       1] == vlob_id
            assert bob.local_operation_storage.storage[vlob_id][5] == True
        if epoch < epoch_to_attack:
            assert (await alice_core.check_operations_epoch(after_epoch=alice.local_operation_storage.epoch,
                                                            before_epoch=alice.local_operation_storage.epoch))[
                       0] == CheckError.NO_ERROR
            assert (await bob_core.check_operations_epoch(after_epoch=bob.local_operation_storage.epoch,
                                                          before_epoch=bob.local_operation_storage.epoch))[
                       0] == CheckError.NO_ERROR
