#!/bin/bash

# Create kind cluster
kind create cluster --config kind-config.yaml

# Install calico CNI plugin
kubectl apply -f https://docs.projectcalico.org/manifests/calico.yaml
kubectl -n kube-system set env daemonset/calico-node FELIX_IGNORELOOSERPF=true

# Install multus CNI
kubectl apply -f https://raw.githubusercontent.com/k8snetworkplumbingwg/multus-cni/master/deployments/multus-daemonset.yml

# Mount BPFFS (sfc-operator requires it, calico mount it on its own if not mounted)
docker exec kind-control-plane mount bpffs /sys/fs/bpf -t bpf -o rw,nosuid,nodev,noexec,relatime,mode=700
docker exec kind-worker mount bpffs /sys/fs/bpf -t bpf -o rw,nosuid,nodev,noexec,relatime,mode=700
docker exec kind-worker2 mount bpffs /sys/fs/bpf -t bpf -o rw,nosuid,nodev,noexec,relatime,mode=700

# Install CRDs for ServiceFunctionChain and LoadBalancer and deploy operator
make install
make deploy