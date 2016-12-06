import sys
import signal
from multiprocessing import Process

from parsec2.vfs import LocalVFSClient, ReqResVFSClient
from parsec2.vfs.mock import VFSServiceMock
from parsec2.ui.fuse import FuseUIServer
from parsec2.broker import ResRepServer


if 0:
    # TODO: WIP
    CONFIG = {
        'services': [
            {
                'name': 'vfs-service-01',
                'class': 'ui.vfs.VFSServiceMock',
                'params': {'mock_path': '...'}
            },
        ],
        'clients': [
            # Connect to external servers
        ],
        'servers': [
            {
                'name': 'ui-01',  # Each server should have an unique name
                'class': 'ui.fuse.FuseUIServer',  # Must be an `abstract.BaseServer` child
                'params': {'mountpoint': '...', 'vfs': 'vfs-01'}
            },
            {
                'name': 'vfs-01',
                'class': 'ui.vfs.VFSMock',  # Must be an `abstract.BaseServer` child
                'params': {'mountpoint': '...', 'vfs': 'vfs-01'}
            },
            'broker.ResRepServer'
            # ...
        ],
    }


def bootstrap_ui(mock_path, mountpoint):
    vfs_service = VFSServiceMock(mock_path)
    vfs_server = ResRepServer(service=vfs_service, addr='tcp://127.0.0.1:5000')
    vfs_server.start()


def bootstrap_vfs(mock_path, mountpoint):
    vfs_client = ReqResVFSClient(addr='tcp://127.0.0.1:5000')
    fuseui = FuseUIServer(mountpoint, vfs_client)
    fuseui.start()


def bootstrap_all(mock_path, mountpoint):
    # TODO: Is that you John Wayne ?
    vfs_service = VFSServiceMock(mock_path)
    vfs_server = ResRepServer(service=vfs_service, addr='tcp://127.0.0.1:5000')
    vfs_client = ReqResVFSClient(addr='tcp://127.0.0.1:5000')
    fuseui = FuseUIServer(mountpoint, vfs_client)

    p1 = Process(target=vfs_server.start)
    p2 = Process(target=fuseui.start)
    p1.start()
    p2.start()

    def graceful_exit():
        p1.terminate()
        p2.terminate()

    signal.signal(signal.SIGINT, graceful_exit)
    signal.signal(signal.SIGTERM, graceful_exit)
    p1.join()
    p2.join()


def bootstrap_nozmq(mock_path, mountpoint):
    vfs_service = VFSServiceMock(mock_path)
    vfs_client = LocalVFSClient(service=vfs_service)
    fuseui = FuseUIServer(mountpoint, vfs_client)

    fuseui.start()


def usage_and_quit():
    print('usage: %s [ui|vfs|all|nozmq]' % sys.argv)
    raise SystemExit(1)


if __name__ == '__main__':
    import logging
    logging.basicConfig(level=logging.DEBUG)
    kwargs = {
        'mock_path': '/home/emmanuel/projects/parsec-cloud/tmp/mocked',
        'mountpoint': '/home/emmanuel/projects/parsec-cloud/tmp/mounted'
    }
    if len(sys.argv) == 2:
        if sys.argv[1] == 'ui':
            bootstrap_ui(**kwargs)
        elif sys.argv[1] == 'vfs':
            bootstrap_vfs(**kwargs)
        elif sys.argv[1] == 'all':
            bootstrap_all(**kwargs)
        elif sys.argv[1] == 'nozmq':
            bootstrap_nozmq(**kwargs)
        else:
            usage_and_quit()
    else:
        usage_and_quit()
