.. image:: docs/parsec_doc_logo.png
    :align: center


======
Parsec
======


.. image:: https://img.shields.io/azure-devops/tests/Scille/parsec/1/master.svg
    :target: https://dev.azure.com/Scille/parsec/_build?definitionId=1&_a=summary
    :alt: Azure DevOps tests

.. image:: https://codecov.io/gh/Scille/parsec-cloud/branch/master/graph/badge.svg
    :target: https://codecov.io/gh/Scille/parsec-cloud
    :alt: Code coverage

.. image:: https://pyup.io/repos/github/Scille/parsec-cloud/shield.svg
    :target: https://pyup.io/repos/github/Scille/parsec-cloud/
    :alt: Updates

.. image:: https://img.shields.io/pypi/v/parsec-cloud.svg
    :target: https://pypi.python.org/pypi/parsec-cloud
    :alt: Pypi Status

.. image:: https://readthedocs.org/projects/parsec-cloud/badge/?version=latest
    :target: http://parsec-cloud.readthedocs.io/en/latest/?badge=latest
    :alt: Documentation Status

.. image:: https://img.shields.io/badge/code%20style-black-000000.svg
    :target: https://github.com/ambv/black
    :alt: Code style: black


Homepage: https://parsec.cloud

Documentation: https://parsec-cloud.readthedocs.org.

Parsec is a free software (AGPL v3) aiming at easily share your work and
data in the cloud in total privacy thanks to cryptographic security.


.. image:: docs/parsec_snapshot.png
    :align: center


Key features:

- Works as a virtual drive on you computer. You can access and modify all the data
  stored in Parsec with your regular softwares just like you would on your local
  hard-drive.
- Never lose any data. Synchronization with the remote server never destroy any
  data, hence you can browse data history and recover from any point in time.
- Client-side cryptographic security. Data and metadata are only visible by you
  and the ones you choose to share with.
- Cryptographic signature. Each modification is signed by it author making trivial
  to identify modifications.
- Cloud provider agnostic. Server provides connectors for S3 and swift object
  storage.
- Simplified enrollment. New user enrollment is simple as sharing a link and a token code.


Installation methods
====================

Windows installer
-----------------
Windows installers are available at https://github.com/Scille/parsec-cloud/releases/latest

Linux Snap
----------
Available for Linux through Snapcraft at https://snapcraft.io/parsec

Python PIP
----------
Parsec is also available directly through PIP for both Linux and Windows with Python > 3.6 with the command:
``pip install parsec-cloud``
(or, if you need to specify Python 3 pip version, ``pip3 install parsec-cloud``)

Iteration 1 : Parsec with metadata stored in Tendermint (1st option using conda)
================================================================================

There are 3 components : Parsec, ABCI server (Application BlockChain Interface), and Tendermint.

We use one virtual environment for parsec and one virtual environment for ABCI server/Tendermint.

Important: make sure you have the executable tendermint version v0.32.6. Go to ``https://github.com/tendermint/tendermint/releases/tag/v0.32.6`` and download ``tendermint_v0.32.6_linux_amd64.zip``, then unzip it.

Switch from vlob memory storage to vlob blockchain storage using ``./tests/scripts/select_db.sh --blockchain`` (or ``./tests/scripts/select_db.sh --mocked`` for mocked storage)

Virtual env need to be create only once.

Requirement 1 : Setup parsec virtual environment
------------------------------------------------
1. ``$ cd <path_to_parsec_cloud>``
2. ``$ conda create -n parsec python=3.7``
3. ``$ conda activate parsec``
4. ``(parsec) $ pip install -e .[all]``
5. ``(parsec) $ python3 setup.py generate_pyqt``


Requirement 2 : Setup ABCI virtual environment
----------------------------------------------
1. ``$ cd <path_to_parsec_cloud>``
2. ``$ conda create -n abci python=3.7``
3. ``$ conda activate abci``
4. ``(abci) $ pip install abci`` (we used v0.6.1, today (02/09/2021) the latest version is v0.8.3)
5. ``(abci) $ pip install -r abci-requirements.txt``

Tests can be done either from gui interface or using pytest.

Tests from GUI interface
------------------------

Terminal 1
##########
1. ``$ cd <path_to_parsec_cloud>``
2. ``$ conda activate abci``
3. ``(abci) $ source tests/scripts/start_blockchain <path_to_tendermint_binary>``

Terminal 2
##########
1. ``$ cd <path_to_parsec_cloud>``
2. ``$ conda activate parsec``
3. ``(parsec) $ source tests/scripts/run_testenv.sh --db BLOCKCHAIN``
4. ``(parsec) $ python3 -m parsec.core.cli gui``

Tests with Pytest
-----------------

Terminal 1
##########
1. ``$ cd <path_to_parsec_cloud>``
2. ``$ conda activate abci``
3. ``(abci) $ source tests/scripts/start_blockchain <path_to_tendermint_binary>``

Terminal 2
##########
1. ``$ cd <path_to_parsec_cloud>``
2. ``$ conda activate parsec``
3. ``(parsec) $ source tests/scripts/run_testenv.sh --db BLOCKCHAIN``
4. ``(parsec) $ python3 -m pytest --blockchain --runslow -k backend/realm``

Iteration 2 : Parsec with metadata stored in Tendermint (2nd option using PyCharm)
==================================================================================
1. Let PyCharm install all requirements.
2. ``$ pip install -e .[all]``
3. ``$ python3 setup.py generate_pyqt``
4. ``$ pip install abci``

Terminal 1
##########
1. ``$ source tests/scripts/start_blockchain <path_to_tendermint_binary>``

Terminal 2
##########
1. ``$ source tests/scripts/run_testenv.sh --db BLOCKCHAIN``
2. ``$ python3 -m pytest --blockchain --runslow -k backend/realm``

Iteration 2 : Parsec with metadata ghost blockchain for verifiable history
==========================================================================
Same installation steps as iteration 1 (``$ pip install -e .[all]``).

Make sure mockup storage is used : ``$ ./tests/scripts/select_db.sh --mocked``

Then launch test with pytest (iteration 2 don't work with gui) : ``$ python3 -m pytest --blockchain --runslow -k backend/realm``
