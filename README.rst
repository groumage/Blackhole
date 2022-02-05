First iteration : Parsec with metadata stored in Tendermint
===========================================================
For the first iteration of the internship (called the first iteration and implemented in the branch parsec-with-blockchain), we chose to relocate the storage of metadata (called Vlob) from the metadata server to the Tendermint blockchain. First objective is to be familiar with Parsec and the source code, second is to show that it is feasible to use a blockchain with Parsec.

We work on data structures used to manage the metadata files in Parsec, the communication between Parsec and Tendermint and how the structures describing the metadata files have been serialized in Tendermint. This work is validate by unit test. We use unit test that are already present in Parsec. More than 95% of those test are validated, which valid our work. Unit test are long (~10 min) since critical path, i.e. access to blockchain, is heavily use. The second iteration of the intership implemented in the branch parsec-with-ghost-blockchain aim at reduce those interactions, in addition with introducing the concept of the ghost blockchain.

Note that tendermint blockchain is used with its executable. We use tendermint executable version v0.32.6(``https://github.com/tendermint/tendermint/releases/tag/v0.32.6`` and download ``tendermint_v0.32.6_linux_amd64.zip`` then extract it).

Launch unit test using terminal
-------------------------------
``$ ./execute_unit_test.sh --terminal <path_to_tendermint_executable>``

Perform test using gui
----------------------
``$ ./execute_unit_test.sh --gui <path_to_tendermint_executable>``

Summary result of unit test
---------------------------
Check that more than 150 tests out of 157 have been validated.

.. image:: docs/result_unit_test.png
  :width: 800
  :align: center
