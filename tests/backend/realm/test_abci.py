import pytest
from uuid import UUID
from pendulum import datetime

from parsec.backend.blockchain.vlob import (
	Vlob,
	Changes,
	Reencryption,
	Encoder,
	VlobKeys,
	ChangesKeys,
	broadcast_tx,
	create_key_vlob,
	retrieve_vlob,
	retrieve_changes,
	create_key_changes,
	create_key_set_vlob_keys,
	retrieve_set_vlob_keys,
	create_key_set_changes_keys,
	retrieve_set_changes_keys,
)

import requests
import base64
import json
from json import JSONEncoder, JSONDecoder

VLOB_ID = UUID("00000000000000000000000000000001")
OTHER_VLOB_ID = UUID("00000000000000000000000000000002")
YET_ANOTHER_VLOB_ID = UUID("00000000000000000000000000000003")
REALM_ID = UUID("A0000000000000000000000000000000")
OTHER_REALM_ID = UUID("B0000000000000000000000000000000")
YET_ANOTHER_REALM_ID = UUID("C0000000000000000000000000000000")

def test_retrieve_vlob(alice):
	blob = b"Whatever content."
	timestamp = datetime(2000, 1, 1)
	sent_vlob = Vlob(REALM_ID, [(blob, alice.device_id, timestamp)])
	broadcast_tx(create_key_vlob(alice.organization_id, VLOB_ID), json.dumps(sent_vlob, cls=Encoder))
	retrieved_vlob = retrieve_vlob(alice.organization_id, VLOB_ID)
	assert sent_vlob == retrieved_vlob

def test_retrieve_vlob_after_blob_updated(alice):
	blob_1 = b"Other whatever content."
	blob_2 = b"Yet another whatever content."
	timestamp_1 = datetime(2000, 1, 1)
	timestamp_2 = datetime(2000, 1, 2)

	sent_vlob_1 = Vlob(REALM_ID, [(blob_1, alice.device_id, timestamp_1)])
	broadcast_tx(create_key_vlob(alice.organization_id, VLOB_ID), json.dumps(sent_vlob_1, cls=Encoder))
	
	sent_vlob_2 = Vlob(REALM_ID, [(blob_2, alice.device_id, timestamp_2)])
	broadcast_tx(create_key_vlob(alice.organization_id, VLOB_ID), json.dumps(sent_vlob_2, cls=Encoder))
	
	retrieved_vlob = retrieve_vlob(alice.organization_id, VLOB_ID)

	assert sent_vlob_1 != retrieved_vlob
	assert sent_vlob_2 == retrieved_vlob

def test_retrieve_default_changes(alice):
	sent_changes = Changes()
	broadcast_tx(create_key_changes(alice.organization_id, REALM_ID), json.dumps(sent_changes, cls=Encoder))
	retrieved_changes = retrieve_changes(alice.organization_id, REALM_ID)
	assert retrieved_changes == Changes()

def test_retrieve_changes_none_reencryption(alice):
	dict_changes = {}
	dict_changes[VLOB_ID] = (alice.device_id, 1, 1)
	sent_changes = Changes(REALM_ID, dict_changes, None)
	sent_changes.checkpoint = 1
	broadcast_tx(create_key_changes(alice.organization_id, REALM_ID), json.dumps(sent_changes, cls=Encoder))
	retrieved_changes = retrieve_changes(alice.organization_id, REALM_ID)
	assert sent_changes == retrieved_changes

def test_retrieve_changes_with_reencryption(alice):
	dict_changes = {}
	blob_1 = b"Whatever content."
	blob_2 = b"Other whatever content."
	timestamp_1 = datetime(2000, 1, 1)
	timestamp_2 = datetime(2000, 1, 2)
	vlob_1 = Vlob(REALM_ID, [(blob_1, alice.device_id, timestamp_1)])
	broadcast_tx(create_key_vlob(alice.organization_id, VLOB_ID), json.dumps(vlob_1, cls=Encoder))
	vlob_2 = Vlob(REALM_ID, [(blob_2, alice.device_id, timestamp_2)]) 
	broadcast_tx(create_key_vlob(alice.organization_id, OTHER_VLOB_ID), json.dumps(vlob_2, cls=Encoder))
	broadcast_tx(create_key_set_vlob_keys(), json.dumps(VlobKeys([(alice.organization_id, VLOB_ID), (alice.organization_id, OTHER_VLOB_ID)]), cls=Encoder))
	items = []
	items.append(((alice.organization_id, VLOB_ID), vlob_1))
	items.append(((alice.organization_id, OTHER_VLOB_ID), vlob_2))
	realm_vlobs = {
        vlob_id: vlob
        for (orgid, vlob_id), vlob in items
        if orgid == alice.organization_id and vlob.realm_id == REALM_ID
    }
	sent_changes = Changes(REALM_ID, dict_changes, Reencryption(REALM_ID, alice.organization_id, realm_vlobs))
	sent_changes.checkpoint = 1
	broadcast_tx(create_key_changes(alice.organization_id, REALM_ID), json.dumps(sent_changes, cls=Encoder))
	retrieved_changes = retrieve_changes(alice.organization_id, REALM_ID)
	assert sent_changes == retrieved_changes

def test_retrieve_key_vlobs(alice):
	sent_vlob_keys = VlobKeys([(alice.organization_id, VLOB_ID), (alice.organization_id, OTHER_VLOB_ID), (alice.organization_id, YET_ANOTHER_VLOB_ID)])
	broadcast_tx(create_key_set_vlob_keys(), json.dumps(sent_vlob_keys, cls=Encoder))
	retrieved_vlob_keys = retrieve_set_vlob_keys()
	assert len(retrieved_vlob_keys.data) == 3
	assert sent_vlob_keys.data == retrieved_vlob_keys.data

def test_retrieve_key_changes(alice):
	sent_changes_keys = ChangesKeys([(alice.organization_id, REALM_ID), (alice.organization_id, OTHER_REALM_ID), (alice.organization_id, YET_ANOTHER_REALM_ID)])
	broadcast_tx(create_key_set_changes_keys(), json.dumps(sent_changes_keys, cls=Encoder))
	retrieved_changes_key = retrieve_set_changes_keys()
	assert len(retrieved_changes_key.data) == 3
	assert sent_changes_keys.data == retrieved_changes_key.data