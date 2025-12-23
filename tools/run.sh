#!/bin/bash 

type=$1
core_min=$2
core_max=$3
cfg_file=$4

if [ "$type" == "debug" ]; then
    ./build-debug/src/pcap_replay_dataplane -l "${core_min}-${core_max}" -- --config $cfg_file

elif [ "$type" == "debug-asan" ]; then
    ./build-debug-asan/src/pcap_replay_dataplane -l "${core_min}-${core_max}" --no-huge -m 4096 -- --config $cfg_file

elif [ "$type" == "debug-asan-gdb" ]; then
    export ASAN_OPTIONS=detect_leaks=0; gdb --args ./build-debug-asan/src/pcap_replay_dataplane -l "${core_min}-${core_max}"  --no-huge -m 4096 -- --config $cfg_file

elif [ "$type" == "release-syms" ]; then
    ./build-release-syms/src/pcap_replay_dataplane -l "${core_min}-${core_max}" -- --config $cfg_file

elif [ "$type" == "release" ]; then
    ./build-release/src/pcap_replay_dataplane -l "${core_min}-${core_max}" -- --config $cfg_file

else
    echo "Usage: $0 [debug|debug-asan|release-syms|release|clean] <core_min> <core_max> [config_file]"
    echo "Example: $0 debug 0 4 (to run on cores 0 to 4) configs/custom.yaml"
    exit 1
fi