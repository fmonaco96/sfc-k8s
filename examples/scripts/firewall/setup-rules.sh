#!/bin/bash


for firewall_pods in $(kubectl get pods | grep firewall-deployment | cut -d " " -f 1)
do
    kubectl exec $firewall_pods \
    # Add rules here
    iptables -A FORWARD -i br-firewall -p icmp --icmp-type echo-request -j DROP
done