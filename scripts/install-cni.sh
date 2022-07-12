#!/bin/sh
echo "Installing static IPAM plugin"
cp /cni-plugins/static /host/opt/cni/bin
echo "static IPAM plugin successfully installed"
echo "Installing sfc-ptp plugin"
cp /cni-plugins/sfc-ptp /host/opt/cni/bin
echo "sfc-ptp plugin successfully installed"