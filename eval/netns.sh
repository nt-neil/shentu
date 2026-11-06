#!/bin/sh
# An "attacker" network namespace inside the VM: 10.99.0.2 (and .3) -> server 10.99.0.1
set -e
ip netns add atk
ip link add va type veth peer name vb
ip link set vb netns atk
ip addr add 10.99.0.1/24 dev va; ip link set va up
ip netns exec atk ip addr add 10.99.0.2/24 dev vb
ip netns exec atk ip addr add 10.99.0.3/24 dev vb
ip netns exec atk ip link set vb up; ip netns exec atk ip link set lo up
