# Parsec Cloud (https://parsec.cloud) Copyright (c) AGPLv3 2019 Scille SAS

import re
import attr
import fnmatch
from uuid import UUID
from pathlib import Path
import importlib_resources
from pendulum import now as pendulum_now
from typing import Optional, Tuple, List, Pattern
from structlog import get_logger
from functools import partial
from async_generator import asynccontextmanager

from parsec.event_bus import EventBus
from parsec.api.protocol import UserID, InvitationType, InvitationDeletedReason
from parsec.api.data import RevokedUserCertificateContent
from parsec.core.types import LocalDevice, UserInfo, DeviceInfo, BackendInvitationAddr
from parsec.core import resources as core_resources
from parsec.core.config import CoreConfig
from parsec.core.backend_connection import (
    BackendAuthenticatedConn,
    BackendConnectionError,
    BackendNotFoundError,
    BackendConnStatus,
    BackendNotAvailable,
)
from parsec.core.invite import (
    UserGreetInitialCtx,
    UserGreetInProgress1Ctx,
    DeviceGreetInitialCtx,
    DeviceGreetInProgress1Ctx,
    InviteAlreadyMemberError,
)
from parsec.core.remote_devices_manager import (
    RemoteDevicesManager,
    RemoteDevicesManagerError,
    RemoteDevicesManagerBackendOfflineError,
    RemoteDevicesManagerNotFoundError,
)
from parsec.core.mountpoint import mountpoint_manager_factory, MountpointManager
from parsec.core.messages_monitor import monitor_messages
from parsec.core.sync_monitor import monitor_sync
from parsec.core.fs import UserFS

from parsec.api.data.entry import EntryID

from parsec.core.core_events import CoreEvent

from parsec.backend.memory.vlob import retrieve_checkpoint, Encoder, ServerOperation
from parsec.core.types.local_device import LocalOperationStorage
from hashlib import sha256
import json
from enum import Enum
from nacl.exceptions import BadSignatureError
from parsec.utils import trio_run
import threading


class CheckError(Enum):
    NO_ERROR = 0
    HASH_HISTORY_ERROR = 1
    SIGNATURE_VALIDITY_ERROR = 2
    TIMESTAMP_VALIDITY_ERROR = 3
    LOCAL_OPERATIONS_ERROR = 4
    ORDERING_OPERATION_ERROR = 5
    EPOCH_ERROR = 6
    REMOVE_OPERATION_ERROR = 7
    HASH_CHAIN_ERROR = 8
    SWITCH_OPERATION_ERROR = 9
    CONTENT_ERROR = 10


abci_addr = 'http://localhost:26657/'

logger = get_logger()

FAILSAFE_PATTERN_FILTER = re.compile(
    r"^\b$"
)  # Matches nothing (https://stackoverflow.com/a/2302992/2846140)


def _get_prevent_sync_pattern(prevent_sync_pattern_path: Path) -> Optional[Pattern]:
    try:
        data = prevent_sync_pattern_path.read_text()
    except OSError as exc:
        logger.warning(
            "Path to the file containing the filename patterns to ignore is not properly defined",
            exc_info=exc,
        )
        return None
    try:
        regex = []
        for line in data.splitlines():
            line = line.strip()
            if line and not line.startswith("#"):
                regex.append(fnmatch.translate(line))
        regex = "|".join(regex)
    except ValueError as exc:
        logger.warning(
            "Could not parse the file containing the filename patterns to ignore", exc_info=exc
        )
        return None
    try:
        return re.compile(regex)
    except re.error as exc:
        logger.warning(
            "Could not compile the file containing the filename patterns to ignore into a regex pattern",
            exc_info=exc,
        )
        return None


def get_prevent_sync_pattern(prevent_sync_pattern_path: Optional[Path] = None) -> Pattern:
    pattern = None
    # Get the pattern from the path defined in the core config
    if prevent_sync_pattern_path is not None:
        pattern = _get_prevent_sync_pattern(prevent_sync_pattern_path)
    # Default to the pattern from the ignore file in the core resources
    if pattern is None:
        with importlib_resources.path(core_resources, "default_pattern.ignore") as path:
            pattern = _get_prevent_sync_pattern(path)
    # As a last resort use the failsafe
    if pattern is None:
        return FAILSAFE_PATTERN_FILTER
    return pattern


@attr.s(frozen=True, slots=True, auto_attribs=True)
class OrganizationStats:
    users: int
    data_size: int
    metadata_size: int


@attr.s(frozen=True, slots=True, auto_attribs=True)
class LoggedCore:
    config: CoreConfig
    device: LocalDevice
    event_bus: EventBus
    local_operation_storage: LocalOperationStorage
    mountpoint_manager: MountpointManager
    user_fs: UserFS
    _remote_devices_manager: RemoteDevicesManager
    _backend_conn: BackendAuthenticatedConn

    def are_monitors_idle(self) -> bool:
        return self._backend_conn.are_monitors_idle()

    async def wait_idle_monitors(self) -> None:
        await self._backend_conn.wait_idle_monitors()

    @property
    def backend_status(self) -> BackendConnStatus:
        return self._backend_conn.status

    @property
    def backend_status_exc(self) -> Optional[Exception]:
        return self._backend_conn.status_exc

    async def find_humans(
        self,
        query: str = None,
        page: int = 1,
        per_page: int = 100,
        omit_revoked: bool = False,
        omit_non_human: bool = False,
    ) -> Tuple[List[UserInfo], int]:
        """
        Raises:
            BackendConnectionError
        """
        rep = await self._backend_conn.cmds.human_find(
            query=query,
            page=page,
            per_page=per_page,
            omit_revoked=omit_revoked,
            omit_non_human=omit_non_human,
        )
        if rep["status"] != "ok":
            raise BackendConnectionError(f"Backend error: {rep}")
        results = []
        for item in rep["results"]:
            # Note `BackendNotFoundError` should never occurs (unless backend is broken !)
            # here given we are feeding the backend the user IDs it has provided us
            user_info = await self.get_user_info(item["user_id"])
            results.append(user_info)
        return (results, rep["total"])

    async def get_organization_stats(self) -> OrganizationStats:
        """
        Raises:
            BackendConnectionError
        """
        rep = await self._backend_conn.cmds.organization_stats()
        if rep["status"] != "ok":
            raise BackendConnectionError(f"Backend error: {rep}")
        return OrganizationStats(
            users=rep["users"], data_size=rep["data_size"], metadata_size=rep["metadata_size"]
        )

    async def get_user_info(self, user_id: UserID) -> UserInfo:
        """
        Raises:
            BackendConnectionError
        """
        try:
            user_certif, revoked_user_certif = await self._remote_devices_manager.get_user(user_id)
        except RemoteDevicesManagerBackendOfflineError as exc:
            raise BackendNotAvailable(str(exc)) from exc
        except RemoteDevicesManagerNotFoundError as exc:
            raise BackendNotFoundError(str(exc)) from exc
        except RemoteDevicesManagerError as exc:
            # TODO: we should be using our own kind of exception instead of borowing BackendConnectionError...
            raise BackendConnectionError(
                f"Error while fetching user {user_id} certificates"
            ) from exc
        return UserInfo(
            user_id=user_certif.user_id,
            human_handle=user_certif.human_handle,
            profile=user_certif.profile,
            revoked_on=revoked_user_certif.timestamp if revoked_user_certif else None,
            created_on=user_certif.timestamp,
        )

    async def get_user_devices_info(self, user_id: UserID = None) -> List[DeviceInfo]:
        """
        Raises:
            BackendConnectionError
        """
        user_id = user_id or self.device.user_id
        try:
            user_certif, revoked_user_certif, device_certifs = await self._remote_devices_manager.get_user_and_devices(
                user_id, no_cache=True
            )
        except RemoteDevicesManagerBackendOfflineError as exc:
            raise BackendNotAvailable(str(exc)) from exc
        except RemoteDevicesManagerNotFoundError as exc:
            raise BackendNotFoundError(str(exc)) from exc
        except RemoteDevicesManagerError as exc:
            # TODO: we should be using our own kind of exception instead of borowing BackendConnectionError...
            raise BackendConnectionError(
                f"Error while fetching user {user_id} certificates"
            ) from exc
        results = []
        for device_certif in device_certifs:
            results.append(
                DeviceInfo(
                    device_id=device_certif.device_id,
                    device_label=device_certif.device_label,
                    created_on=device_certif.timestamp,
                )
            )
        return results

    async def revoke_user(self, user_id: UserID) -> None:
        """
        Raises:
            BackendConnectionError
        """
        now = pendulum_now()
        revoked_user_certificate = RevokedUserCertificateContent(
            author=self.device.device_id, timestamp=now, user_id=user_id
        ).dump_and_sign(self.device.signing_key)
        rep = await self._backend_conn.cmds.user_revoke(
            revoked_user_certificate=revoked_user_certificate
        )
        if rep["status"] != "ok":
            raise BackendConnectionError(f"Error while trying to revoke user {user_id}: {rep}")

        # Invalidate potential cache to avoid displaying the user as not-revoked
        self._remote_devices_manager.invalidate_user_cache(user_id)

    async def new_user_invitation(self, email: str, send_email: bool) -> BackendInvitationAddr:
        """
        Raises:
            InviteAlreadyMemberError
            BackendConnectionError
        """
        rep = await self._backend_conn.cmds.invite_new(
            type=InvitationType.USER, claimer_email=email, send_email=send_email
        )
        if rep["status"] == "already_member":
            raise InviteAlreadyMemberError()
        elif rep["status"] != "ok":
            raise BackendConnectionError(f"Backend error: {rep}")
        return BackendInvitationAddr.build(
            backend_addr=self.device.organization_addr,
            organization_id=self.device.organization_id,
            invitation_type=InvitationType.USER,
            token=rep["token"],
        )

    async def new_device_invitation(self, send_email: bool) -> BackendInvitationAddr:
        """
        Raises:
            BackendConnectionError
        """
        rep = await self._backend_conn.cmds.invite_new(
            type=InvitationType.DEVICE, send_email=send_email
        )
        if rep["status"] != "ok":
            raise BackendConnectionError(f"Backend error: {rep}")
        return BackendInvitationAddr.build(
            backend_addr=self.device.organization_addr,
            organization_id=self.device.organization_id,
            invitation_type=InvitationType.DEVICE,
            token=rep["token"],
        )

    async def delete_invitation(
        self, token: UUID, reason: InvitationDeletedReason = InvitationDeletedReason.CANCELLED
    ) -> None:
        """
        Raises:
            BackendConnectionError
        """
        rep = await self._backend_conn.cmds.invite_delete(token=token, reason=reason)
        if rep["status"] != "ok":
            raise BackendConnectionError(f"Backend error: {rep}")

    async def list_invitations(self) -> List[dict]:  # TODO: better return type
        """
        Raises:
            BackendConnectionError
        """
        rep = await self._backend_conn.cmds.invite_list()
        if rep["status"] != "ok":
            raise BackendConnectionError(f"Backend error: {rep}")
        return rep["invitations"]

    async def start_greeting_user(self, token: UUID) -> UserGreetInProgress1Ctx:
        """
        Raises:
            BackendConnectionError
            InviteError
        """
        initial_ctx = UserGreetInitialCtx(cmds=self._backend_conn.cmds, token=token)
        return await initial_ctx.do_wait_peer()

    async def start_greeting_device(self, token: UUID) -> DeviceGreetInProgress1Ctx:
        """
        Raises:
            BackendConnectionError
            InviteError
        """
        initial_ctx = DeviceGreetInitialCtx(cmds=self._backend_conn.cmds, token=token)
        return await initial_ctx.do_wait_peer()

    async def check_operations_epoch(self, after_epoch: int, before_epoch: int) -> [CheckError, EntryID]:
        # we assume we checks epoch operations one by one
        assert after_epoch == before_epoch

        # Note that only before_epoch is used (all checks valid -> new epoch = before_epoch + 1).
        # after_epoch could be used later to check 2 epochs at a time (for instance if a device disconnected during 2 epochs or more)

        def parse_signature(sig):
            element_sig = sig.decode('utf-8')
            element_sig = element_sig[:-1]
            element_sig = element_sig[1:]
            content = element_sig.split(',')
            return content

        def get_version_from_sig(sig):
            sig = json.loads(sig.decode('utf-8'))
            if sig['version'] == 'None':
                return None
            else:
                return int(sig['version'])

        def get_timestamp_from_sig(sig):
            sig = json.loads(sig.decode('utf-8'))
            if sig['timestamp'] == 'None':
                return None
            else:
                return sig['timestamp'].__str__()

        def get_ciphered_from_sig(sig):
            sig = json.loads(sig.decode('utf-8'))
            return sig['ciphered']

        latest_safe_content = {}
        latest_hash = {}

        for vlob_id in list(self.device.local_operation_storage.storage.keys()):
            v = self.device.local_operation_storage.storage[vlob_id]
            get_last_write = False
            rep = None
            sig = None

            # step 3 from protocole de fin d'epoch : get checkpoint from blockchain
            list_checkpoints_from_blockchain = retrieve_checkpoint(self.device.organization_id, vlob_id)
            version_checkpoint_from_blockchain = \
            list_checkpoints_from_blockchain.checkpoints[len(list_checkpoints_from_blockchain.checkpoints) - 1][2]
            hash_checkpoint_from_blockchain = \
            list_checkpoints_from_blockchain.checkpoints[len(list_checkpoints_from_blockchain.checkpoints) - 1][1]

            # step 4 from protocole : update current_version if version_checkpoint_from_blockchain > current_version
            # (v[3] = current_version)
            if version_checkpoint_from_blockchain > v[3]:
                v_list = list(v)
                v_list[3] = version_checkpoint_from_blockchain
                v = tuple(v_list)
                self.device.local_operation_storage.storage[vlob_id] = v

            # step 5 from protocole de fin d'epoch : request history
            # (v[2] = safe_version)
            rep = await self._backend_conn.cmds.vlob_history(vlob_id=vlob_id, after_version=v[2] + 1,
                                                             before_version=version_checkpoint_from_blockchain)
            if rep["status"] != "ok":
                raise BackendConnectionError(f"Backend error: {rep}")

            # step 6 from protocole de fin d'epoch : check equality hash latest operation from history and hash from blockchain
            # (v[5] = is_corrupted_boolean)
            last_op_hist = rep['history'][len(rep['history']) - 1]
            op_to_hash = ServerOperation((last_op_hist['version'], last_op_hist['author'], last_op_hist['timestamp'],
                                          last_op_hist['hash_obj_after_operation'], last_op_hist['hash_prev_digest'],
                                          last_op_hist['signature'], last_op_hist['is_read_op']))
            hash_last_op = sha256(bytes(json.dumps(op_to_hash, cls=Encoder), encoding='utf-8')).hexdigest().__str__()

            if hash_checkpoint_from_blockchain != hash_last_op:
                v_list = list(v)
                v_list[5] = True
                v = tuple(v_list)
                self.device.local_operation_storage.storage[vlob_id] = v
                return [CheckError.HASH_HISTORY_ERROR, vlob_id]

            mem_version = version_checkpoint_from_blockchain + 1
            for i in range(len(rep['history']) - 1, -1, -1):

                # step 7 from protocole de fin d'epoch : check signature validity
                # (v[5] = is_corrupted_boolean)
                if rep['history'][i]['author'] == self.device.device_id:
                    try:
                        sig = self.device.signing_key.verify_key.verify(rep['history'][i]['signature'])
                    except BadSignatureError:
                        v_list = list(v)
                        v_list[5] = True
                        v = tuple(v_list)
                        self.device.local_operation_storage.storage[vlob_id] = v
                        return [CheckError.SIGNATURE_VALIDITY_ERROR, vlob_id]
                else:
                    sender = await self.user_fs.remote_loader.get_device(rep['history'][i]['author'])
                    try:
                        sig = sender.verify_key.verify(rep['history'][i]['signature'])
                    except BadSignatureError:
                        v_list = list(v)
                        v_list[5] = True
                        v = tuple(v_list)
                        self.device.local_operation_storage.storage[vlob_id] = v
                        return [CheckError.SIGNATURE_VALIDITY_ERROR, vlob_id]

                # step 8 from protocole de fin d'epoch : check there is no switching operation in the history
                version_from_sig = get_version_from_sig(sig)
                if version_from_sig != None:
                    # is equal iff write operation is follow by read operation (or read operation followed by another read operation)
                    if version_from_sig > mem_version:
                        v_list = list(v)
                        v_list[5] = True
                        v = tuple(v_list)
                        self.device.local_operation_storage.storage[vlob_id] = v
                        return [CheckError.SWITCH_OPERATION_ERROR, vlob_id]
                    mem_version = version_from_sig

                # step 9 from protocole de fin d'epoch : check previous hash validity
                if i == 0:
                    # check if first operation of the epoch is well chained to the last operation of previous epoch
                    if rep['history'][i]['hash_prev_digest'] != v[4]:
                        v_list = list(v)
                        v_list[5] = True
                        v = tuple(v_list)
                        self.device.local_operation_storage.storage[vlob_id] = v
                        return [CheckError.HASH_CHAIN_ERROR, vlob_id]
                else:
                    # check operation are well chained within an epoch
                    prev_elt = rep['history'][i - 1]
                    prev_elt_to_op = ServerOperation((prev_elt['version'], prev_elt['author'], prev_elt['timestamp'],
                                                      prev_elt['hash_obj_after_operation'],
                                                      prev_elt['hash_prev_digest'], prev_elt['signature'],
                                                      prev_elt['is_read_op']))
                    hash_prev_op = sha256(
                        bytes(json.dumps(prev_elt_to_op, cls=Encoder), encoding='utf-8')).hexdigest().__str__()

                    if rep['history'][i]['hash_prev_digest'] != hash_prev_op:
                        v_list = list(v)
                        v_list[5] = True
                        v = tuple(v_list)
                        self.device.local_operation_storage.storage[vlob_id] = v
                        return [CheckError.HASH_CHAIN_ERROR, vlob_id]

                # step 10 from protocole de fin d'epoch : check timestamp validity
                timestamp_from_sig = get_timestamp_from_sig(sig)
                if timestamp_from_sig != None:
                    # some operation are sent with 'None' timestamp
                    if timestamp_from_sig != rep['history'][i]['timestamp'].__str__():
                        v_list = list(v)
                        v_list[5] = True
                        v = tuple(v_list)
                        self.device.local_operation_storage.storage[vlob_id] = v
                        return [CheckError.TIMESTAMP_VALIDITY_ERROR, vlob_id]

                # step 11 from protocole de fin d'epoch : update last safe content
                # WARNING: to be tested.
                if rep['history'][i]['is_read_op'] == False:
                    latest_safe_content[vlob_id] = get_ciphered_from_sig(sig)

            # step 12 from protocole de fin d'epoch : check no remove operations
            history_device_operation = list(filter(lambda x: x['author'] == self.device.device_id, rep['history']))
            if len(history_device_operation) != len(self.device.local_operation_storage.storage[vlob_id][1]):
                v_list = list(v)
                v_list[5] = True
                v = tuple(v_list)
                self.device.local_operation_storage.storage[vlob_id] = v
                return [CheckError.REMOVE_OPERATION_ERROR, vlob_id]

            # step 13 from protocole de fin d'epoch : check validity of content read
            # check that data read are equal to the last data which has been wrote (by the client itself or someone else).
            # WARNING: to be finished and to be tested. Is it working if there is only read operation in the history ?

            # for each Tuple[version, content_read]
            # (v[6] is List[Tuple[version, content_read]])
            for elt in v[6]:
                last_write_op_of_specific_version = list(
                    filter(lambda x: x['version'] == elt[0] and x['is_read_op'] == False, rep['history']))
                if len(last_write_op_of_specific_version) != 0:
                    sig = last_write_op_of_specific_version[0]['signature']
                    if last_write_op_of_specific_version[0]['author'] == self.device.device_id:
                        sig = self.device.signing_key.verify_key.verify(sig)
                    else:
                        sender = await self.user_fs.remote_loader.get_device(
                            last_write_op_of_specific_version[0]['author'])
                        sig = sender.verify_key.verify(sig)
                    if elt[1].__str__() != get_ciphered_from_sig(sig):
                        return [CheckError.CONTENT_ERROR, vlob_id]
            v_list = list(v)
            v_list[2] = version_checkpoint_from_blockchain
            self.device.local_operation_storage.storage[vlob_id] = v_list

            last_digest_vlob = rep['history'][len(rep['history']) - 1]
            json_last_digest_vlob = ServerOperation((last_digest_vlob['version'], last_digest_vlob['author'],
                                                     last_digest_vlob['timestamp'],
                                                     last_digest_vlob['hash_obj_after_operation'],
                                                     last_digest_vlob['hash_prev_digest'],
                                                     last_digest_vlob['signature'], last_digest_vlob['is_read_op']))
            latest_hash[vlob_id] = sha256(
                bytes(json.dumps(json_last_digest_vlob, cls=Encoder), encoding='utf-8')).hexdigest().__str__()
        self.device.local_operation_storage.update_epoch_device(before_epoch + 1, latest_safe_content, latest_hash)

        return [CheckError.NO_ERROR, None]

    async def on_epoch_event_finished(self, event, epoch: int):
        # In the unit test, check_operations_epoch is manually invoked. We don't explore a way to automatic invoked that method when epoch_finished_event is received.
        # However, we checked that method on_epoch_event_finished is well invoked whenever epoch_finished_event is received.

        # error_type, faulty_vlob = await self.check_operations_epoch(after_epoch=epoch, before_epoch=epoch)
        pass


@asynccontextmanager
async def logged_core_factory(
    config: CoreConfig, device: LocalDevice, event_bus: Optional[EventBus] = None
):
    event_bus = event_bus or EventBus()
    prevent_sync_pattern = get_prevent_sync_pattern(config.prevent_sync_pattern_path)
    local_operation_storage = LocalOperationStorage(storage={}, epoch=0)

    backend_conn = BackendAuthenticatedConn(
        addr=device.organization_addr,
        device_id=device.device_id,
        signing_key=device.signing_key,
        event_bus=event_bus,
        max_cooldown=config.backend_max_cooldown,
        max_pool=config.backend_max_connections,
        keepalive=config.backend_connection_keepalive,
    )

    path = config.data_base_dir / device.slug
    remote_devices_manager = RemoteDevicesManager(backend_conn.cmds, device.root_verify_key)
    async with UserFS.run(
        device, path, backend_conn.cmds, remote_devices_manager, event_bus, prevent_sync_pattern
    ) as user_fs:
        backend_conn.register_monitor(partial(monitor_messages, user_fs, event_bus))
        backend_conn.register_monitor(partial(monitor_sync, user_fs, event_bus))

        async with backend_conn.run():
            async with mountpoint_manager_factory(
                user_fs,
                event_bus,
                config.mountpoint_base_dir,
                mount_all=config.mountpoint_enabled,
                mount_on_workspace_created=config.mountpoint_enabled,
                mount_on_workspace_shared=config.mountpoint_enabled,
                unmount_on_workspace_revoked=config.mountpoint_enabled,
                exclude_from_mount_all=config.disabled_workspaces,
            ) as mountpoint_manager:
                logged_core = LoggedCore(
                    config=config,
                    device=device,
                    event_bus=event_bus,
                    local_operation_storage=local_operation_storage,
                    mountpoint_manager=mountpoint_manager,
                    user_fs=user_fs,
                    remote_devices_manager=remote_devices_manager,
                    backend_conn=backend_conn,
                )

                def fct_callback_check_operations(event, epoch):
                    t = threading.Thread(target=trio_run, args=[logged_core.on_epoch_event_finished, event, epoch])
                    t.start()

                event_bus.connect(CoreEvent.BACKEND_REALM_EPOCH_FINISHED, fct_callback_check_operations)
                yield logged_core
