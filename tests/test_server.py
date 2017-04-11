import pytest
import json
from asyncio import Future

from parsec.service import BaseService, service, event, cmd
from parsec.server import BaseServer

from tests.common import MockedContext


@pytest.fixture
def server():
    return BaseServer()


@pytest.fixture
def services():
    class RootService(BaseService):
        pass

    class NodeAService(BaseService):
        _root = service('RootService')

    class NodeBService(BaseService):
        _root = service('RootService')

    class LeafService(BaseService):
        _nodea = service('NodeAService')
        _nodeb = service('NodeBService')

    return RootService, NodeAService, NodeBService, LeafService


def test_services_dependencies_good(server, services):
    RootService, NodeAService, NodeBService, LeafService = services

    sroot = RootService()
    snodea = NodeAService()
    snodeb = NodeBService()
    sleaf = LeafService()
    server.register_service(sroot)
    server.register_service(snodea)
    server.register_service(snodeb)
    server.register_service(sleaf)

    server.bootstrap_services()

    assert snodea._root is sroot
    assert snodeb._root is sroot
    assert sleaf._nodea is snodea
    assert sleaf._nodeb is snodeb


def test_services_dependencies_missing_dep(server, services):
    _, NodeAService, _, _ = services

    snodea = NodeAService()
    server.register_service(snodea)

    with pytest.raises(RuntimeError) as exc:
        server.bootstrap_services()
    assert exc.value.args[0] == ['Service `NodeAService` required unknown service `RootService`']


def test_services_dependencies_missing_multi_dep(server, services):
    _, NodeAService, NodeBService, LeafService = services

    snodea = NodeAService()
    snodeb = NodeBService()
    sleaf = LeafService()
    server.register_service(snodea)
    server.register_service(snodeb)
    server.register_service(sleaf)

    with pytest.raises(RuntimeError) as exc:
        server.bootstrap_services()
    assert sorted(exc.value.args[0]) == sorted([
        'Service `NodeAService` required unknown service `RootService`',
        'Service `NodeBService` required unknown service `RootService`'
    ])


def test_services_dependencies_child(server, services):
    RootService, NodeAService, _, _ = services

    class ChildService(NodeAService):
        _nodea = service('NodeAService')

    schild = ChildService()
    sroot = RootService()
    snodea = NodeAService()
    server.register_service(schild)
    server.register_service(sroot)
    server.register_service(snodea)

    server.bootstrap_services()
    assert schild._root is sroot
    assert schild._nodea is snodea


@pytest.fixture
def server_pingpong(server):
    class PingPongService(BaseService):
        on_ping = event('on_ping')

        @cmd('ping')
        async def ping(self, session, cmd):
            self.on_ping.send(cmd['ping'])
            return {'status': 'ok', 'pong': cmd['ping']}

    server.register_service(PingPongService())
    return server


@pytest.mark.asyncio
async def test_register_event(server_pingpong):

    # 1 - Client register for on_event with sender foo
    # 2 - Client send ping command with sender bar (should not trigger notification)
    # 3 - Client send ping with sender foo
    # 4 - Server send notification for event ping@foo
    history = []
    client_close_connexion = Future()

    async def on_send(body):
        msg = json.loads(body.decode())
        history.append(('send', msg))
        if 'event' in msg:
            # Last message in our test has happened
            client_close_connexion.set_result(None)

    recv_msgs = [
        {'cmd': 'subscribe', 'event': 'on_ping', 'sender': 'foo'},
        {'cmd': 'PingPongService:ping', 'ping': 'bar'},
        {'cmd': 'PingPongService:ping', 'ping': 'foo'}
    ]
    recv_msgs.reverse()

    async def on_recv():
        msg = recv_msgs.pop() if recv_msgs else None
        if msg is None:
            # No more message, wait and close connection (i.e. return None)
            await client_close_connexion
            history.append(('recv', msg))
        else:
            history.append(('recv', msg))
            return json.dumps(msg).encode()

    ctx = MockedContext(on_recv, on_send)
    await server_pingpong.on_connection(ctx)

    assert history == [
        ('recv', {'sender': 'foo', 'cmd': 'subscribe', 'event': 'on_ping'}),
        ('send', {'status': 'ok'}),
        ('recv', {'cmd': 'PingPongService:ping', 'ping': 'bar'}),
        ('send', {'pong': 'bar', 'status': 'ok'}),
        ('recv', {'cmd': 'PingPongService:ping', 'ping': 'foo'}),
        ('send', {'pong': 'foo', 'status': 'ok'}),
        ('send', {'event': 'on_ping', 'sender': 'foo'}),
        ('recv', None)
    ]
