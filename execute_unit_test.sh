./tests/scripts/select_db.sh --mocked
gnome-terminal -- python3 -m pytest --blockchain --runslow -k backend/realm
