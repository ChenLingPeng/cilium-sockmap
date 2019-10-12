#!/bin/bash

make -C bpf/sockops clean
make -C bpf/sockops

bpftool -m prog load bpf/sockops/bpf_sockops.o "/sys/fs/bpf/bpf_sockop"
bpftool cgroup attach "/sys/fs/cgroup/unified/" sock_ops pinned "/sys/fs/bpf/bpf_sockop"
MAP_ID=$(sudo bpftool prog show pinned "/sys/fs/bpf/bpf_sockop" | grep -o -E 'map_ids [0-9]+' | awk '{print $2}')
bpftool map pin id $MAP_ID "/sys/fs/bpf/sock_ops_map"
bpftool -m prog load bpf/sockops/bpf_redir.o "/sys/fs/bpf/bpf_redir" map name sock_ops_map pinned "/sys/fs/bpf/sock_ops_map"
bpftool prog attach pinned "/sys/fs/bpf/bpf_redir" msg_verdict pinned "/sys/fs/bpf/sock_ops_map"

