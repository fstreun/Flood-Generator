# Flood Generator

A simple framework to implement high-rate flooding attacks on commodity hardware.
The framework is build with libmoon (https://github.com/libmoon/libmoon), a Lua wrapper for DPDK.

Look into libmoon (and DPDK) to get familiar with the environment.
Read and try the our examples to understand how our framework can be used to implement and perform high-rate flooding attacks.

## Perform Flooding Attack

```
sudo ./path/to/libmoon examples/generic/udpFlood.lua [arguments]
```