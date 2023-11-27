#!/bin/bash
firewall_pods=$(kubectl get pods | grep firewall-deployment | cut -d " " -f 1)

for firewall_pod in $firewall_pods;
do
    kubectl exec $firewall_pod --\
    iptables -L FORWARD -Z 
done
