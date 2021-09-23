import logging
import os

from math import ceil
import rlp
from trie.db.memory import MemoryDB
from rlp.sedes import big_endian_int, binary
from abci import (
    ABCIServer,
    BaseApplication,
    ResponseInfo,
    ResponseCheckTx, ResponseDeliverTx,
    ResponseQuery,
    ResponseCommit,
    CodeTypeOk,
)

logging.basicConfig(level=os.environ.get("LOGLEVEL", "NOTSET"))
logger = logging.getLogger(__name__)

STATE_KEY = b'stateKey'
KV_PAIR_PREFIX_KEY = b'kvPairKey'
BLANK_ROOT_HASH = b''


def prefix_key(key):
    """Takes key as a byte string and returns a byte string
    """
    return KV_PAIR_PREFIX_KEY + key


class stateMetaData(rlp.Serializable):
    fields = [
        ('size', big_endian_int),
        ('height', big_endian_int),
        ('apphash', binary)
    ]

    def __init__(self, size, height, apphash):
        super().__init__(size, height, apphash)


class State(object):
    """
    Talks directly to cold storage and the merkle
    only
    """

    def __init__(self, db, size, height, apphash):
        self.db = db
        self.size = size
        self.height = height
        self.apphash = apphash

    @classmethod
    def load_state(cls, dbfile=None):
        """ Create or load State.
        returns: State
        """
        if not dbfile:
            return (cls(MemoryDB(), 0, 0, BLANK_ROOT_HASH))

    def save(self):
        # Save to storage
        meta = stateMetaData(self.size, self.height, self.apphash)
        serial = rlp.encode(meta, sedes=stateMetaData)
        self.db.set(STATE_KEY, serial)
        return self.apphash


class MetadataBlockchain(BaseApplication):

    def __init__(self):
        self.state = State.load_state()

    def info(self, req):
        """
        Since this will always respond with height=0, Tendermint
        will resync this app from the begining
        """
        r = ResponseInfo()
        r.version = "1.0"
        r.last_block_height = self.state.height
        r.last_block_app_hash = b''
        return r

    def deliver_tx(self, tx):
        """Validate the transaction before mutating the state.

        Args:
            raw_tx: a raw string (in bytes) transaction.
        """
        parts = tx.split(b'&')
        key, value = parts[0], parts[1]
        key_content = key.split(b'?')[1]
        value_content = value.split(b'?')[1]
        logger.info("Transaction received")
        logger.info("%s <-> %s", key_content, value_content)
        self.state.db.set(prefix_key(key_content), value_content)
        self.state.size += 1
        logger.info("Transaction successfully delivered")
        return ResponseDeliverTx(code=CodeTypeOk)

    def check_tx(self, tx):
        return ResponseCheckTx(code=CodeTypeOk)

    def commit(self):
        byte_length = max(ceil(self.state.size.bit_length() / 8), 1)
        app_hash = self.state.size.to_bytes(byte_length, byteorder='big')
        self.state.app_hash = app_hash
        self.state.height += 1
        self.state.save()
        return ResponseCommit(data=app_hash)

    def query(self, req):
        logger.info("Query received")
        if self.state.db.exists(prefix_key(req.data)):
            value = self.state.db.get(prefix_key(req.data))
            logger.info("%s <-> %s", req.data, value)
            logger.info("Query successfully delivered")
            return ResponseQuery(code=CodeTypeOk, value=value)
        else:
            if not self.state.db.exists(prefix_key(b'0')):
                self.state.db.set(prefix_key(b'0'), b'0')
            value = self.state.db.get(prefix_key(b'0'))
            logger.info("%s <-> %s", req.data, value)
            logger.info("Query successfully delivered")
            return ResponseQuery(code=CodeTypeOk, value=value)


if __name__ == '__main__':
    app = ABCIServer(app=MetadataBlockchain())
    app.run()
