#!/bin/bash

while :
firewall_pods=$(kubectl get pods | grep firewall-deployment | cut -d " " -f 1)
do
    text=""
    for firewall_pod in $firewall_pods;
    do
        text+="$(kubectl exec $firewall_pod --\
        iptables -L FORWARD -v -n)\n"
    done
    clear
    echo -e $text
    sleep 0.5
done
