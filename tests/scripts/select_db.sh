if [ "$#" -ne 1 ]; then
    echo "You must enter exactly 1 argument: --mocked or --blockchain"
else
	if [ $1 = "--mocked" ]
	then
	        sed 's/--db BLOCKCHAIN/--db MOCKED/g' tests/scripts/run_testenv.py > tests/scripts/run_testenv_tmp.py
                chmod +x tests/scripts/run_testenv_tmp.py
	        sed 's/return "BLOCKCHAIN"/return "MOCKED"/g' tests/conftest.py > tests/conftest_tmp.py
                chmod +x tests/conftest_tmp.py
		rm -rf tests/scripts/run_testenv.py
		mv tests/scripts/run_testenv_tmp.py tests/scripts/run_testenv.py
		rm -rf tests/conftest.py
		mv tests/conftest_tmp.py tests/conftest.py
	fi
	if [ $1 = "--blockchain" ]
	then
		sed 's/--db MOCKED/--db BLOCKCHAIN/g' tests/scripts/run_testenv.py > tests/scripts/run_testenv_tmp.py
                chmod +x tests/scripts/run_testenv_tmp.py
		sed 's/return "MOCKED"/return "BLOCKCHAIN"/g' tests/conftest.py > tests/conftest_tmp.py
                chmod +x tests/conftest_tmp.py
		rm -rf tests/scripts/run_testenv.py
		mv tests/scripts/run_testenv_tmp.py tests/scripts/run_testenv.py
		rm -rf tests/conftest.py
		mv tests/conftest_tmp.py tests/conftest.py
	fi
fi
