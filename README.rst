First stage : Parsec with metadata stored in Tendermint
=======================================================
For the first stage of the internship (called the first iteration and implemented in the branch parsec-with-blockchain), we chose to relocate the storage of metadata (called Vlob) from the metadata server to the Tendermint blockchain.

We work on data structures used to manage the metadata files in Parsec, the communication between Parsec and Tendermint and how the structures describing the metadata files have been serialized in Tendermint. This work is validate by unit test. We use unit test that are already present in Parsec. More than 95% of those test are validated, which valid our work.

Launch unit test using terminal
-------------------------------
``$ ./execute_unit_test.sh --terminal``

Launch unit test using gui
--------------------------
``$ ./execute_unit_test.sh --gui``
