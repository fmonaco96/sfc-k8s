#!/bin/sh
#static plugin may be needed
echo "Removing sfc-ptp plugin"
rm -f /host/opt/cni/bin/sfc-ptp
echo "sfc-ptp plugin successfully removed"