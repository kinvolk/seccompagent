---
title: Installation
weight: 10
description: >
  How to install.
---

Seccomp Agent is a DaemonSet deployed in the cluster and relies on new features in runc.

## Installing Seccomp Agent

Requirements:
- Linux >= 5.9
- libseccomp >= 2.5.2
- runc >= 1.1.0
- containerd >= 1.5.5

Recommended:
- Flatcar Container Linux >= 3127.0.0
- containerd >= 1.6.0-rc1
- Security Profiles Operator (SPO) >= v0.4.1 (unreleased) or from git main

### With Typhoon on Azure

In the `docs/terraform` directory, you can find terraform files to start a
Kubernetes cluster with the required dependencies.

Please see the [Azure tutorial](https://typhoon.psdn.io/flatcar-linux/azure/)
from the [Typhoon](https://github.com/poseidon/typhoon) documentation.

### Deploy the Seccomp Agent DaemonSet

```
kubectl apply -f deploy/seccompagent.yaml
```

### Deploy a pod with a Seccomp Profile

If you use the [Security Profiles Operator
(SPO)](https://github.com/kubernetes-sigs/security-profiles-operator), you can
deploy a Seccomp Profile with kubectl:

```
kubectl apply -f docs/profiles/notify-dangerous.yaml
```

Otherwise, you can install `docs/profiles/notify-dangerous.json` on the worker
nodes manually, in the `/var/lib/kubelet/seccomp/` directory.


Start a new pod:

```
kubectl apply -f docs/examples/pod.yaml
```
