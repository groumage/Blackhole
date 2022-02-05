Iteration 1 : Parsec with metadata stored in Tendermint
=======================================================
The first iteration is to relocate metadata from the parsec backend to Tendermint (all other data stay in the backend).

Metadata are serialize/deserialize to/from Tendermint. Read/write/update function are overwrite.

Launch unit test using terminal
-------------------------------
``$ ./execute_unit_test.sh --terminal``

Launch unit test using gui
--------------------------
``$ ./execute_unit_test.sh --gui``
