# Deploying on Kubernetes

## Pre-req for DP

Installation and setup of Multus, SR-IOV device plugin is described
[here](https://github.com/clearlinux/cloud-native-setup/tree/master/clr-k8s-examples/9-multi-network)

## DP

[`dp.yaml`](dp.yaml) deploys SPGW-U pod on k8s. Our DP needs two interfaces and
k8s is not multi-network aware. We rely on
[Multus](https://github.com/intel/multus-cni) CNI to provide the extra
interfaces from networks `s1u-net` and `sgi-net`. These extra networks are
defined in [dp-nets.yaml](dp-nets.yaml). DP can be used with or without
hugepages, with or without DPDK bound device (`AF_PACKET` vdev). Check the
commented out sections.

We rely on
[sriov-network-device-plugin](https://github.com/intel/sriov-network-device-plugin)
to populate SR-IOV VFs as k8s resources to be consumed in a k8s native way. In
our case `intel.com/sriov_vfio: '2'` conveys we need 2 VFs. This identifier also
appears in the network definition linking the resource pool and the network.

`launch.sh` substitutes `CP_ADDR` and `DP_ADDR` in `interface.cfg` file, sources
`dp_config.cfg` and runs the binary.

## CP

This deploys SPGW-C pod on k8s. Currently it requires S1U IP of DP as part of
the launch commandline. To get this info we have an `initContainer` with
appropriate permissions to read the `k8s.v1.cni.cncf.io/networks-status` from DP
pod spec, populated by `Multus` with the IPs from the `s1u` and `sgi` networks
k8s is unaware of. Another alternative is to manually provide this value as an
env variable (currently commented out).

Apart from this, the CP container spec itself is straightforward. There is a
`launch.sh` which substitutes templates for `CP_ADDR` and `DP_ADDR` in the
`interface.cfg` file, sources `cp_config.cfg` and runs the binary.