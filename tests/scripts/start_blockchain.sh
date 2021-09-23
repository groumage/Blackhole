if [ "$#" -ne 1 ]; then
    echo "You must enter exactly 1 argument: <path_to_tendermint_binary>"
else
	if [[ -z "${TMHOME}" ]]; then
                export TMHOME=$HOME/.tendermint
        fi
	rm -rf $TMHOME/*
	$1 init
	sed 's/skip_timeout_commit = false/skip_timeout_commit = true/g' $TMHOME/config/config.toml > $TMHOME/config/config_tmp.toml
	rm -rf $TMHOME/config/config.toml
	mv $TMHOME/config/config_tmp.toml $TMHOME/config/config.toml
	sed 's/create_empty_blocks = true/create_empty_blocks = false/g' $TMHOME/config/config.toml > $TMHOME/config/config_tmp.toml
	rm -rf $TMHOME/config/config.toml
	mv $TMHOME/config/config_tmp.toml $TMHOME/config/config.toml
	sed 's/cache_size = 10000/cache_size = 0/g' $TMHOME/config/config.toml > $TMHOME/config/config_tmp.toml
	rm -rf $TMHOME/config/config.toml
	mv $TMHOME/config/config_tmp.toml $TMHOME/config/config.toml
	gnome-terminal -- python3 abci_server.py
	$1 node
fi
