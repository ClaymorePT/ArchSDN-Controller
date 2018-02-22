#!/usr/bin/env bash

source ~/PythonVirtEnv/testing/bin/activate
echo "Port: $1"
python3 -d ~/PythonVirtEnv/testing/bin/ryu-manager --config-file ryu.conf --verbose --enable-debugger --default-log-level 10 --log-dir logs --log-file "$1".log --ofp-tcp-listen-port "$1"  --user-flags ArchSDN_opts.py  --archSDN_config=./configs/controller_"$1".ini ArchSDN.py
