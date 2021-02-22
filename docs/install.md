---
title: Installation
weight: 10
description: >
  How to install.
---

Seccomp Agent is a DaemonSet deployed in the cluster and relies on new features in runc.

## Installing Seccomp Agent

Requirements:
- libseccomp-2.5.0 or more.
- runc built from our dev branch
- container CRI built with runtime-spec revendored from our dev branch
- Linux 5.9 or more.

Start runc:
```
git clone git@github.com:kinvolk/runc.git
cd runc
git checkout mauricio/seccomp-notify-listener-path
make all
```

Get containerd:
```
# Do this in $GOPATH/src/github.com/containerd/, it fails to build otherwise.
git clone git@github.com:kinvolk/containerd.git
cd containerd
git checkout alban_seccomp_notify
make all
sudo make install
```

Start containerd CRI:
```
# Make sure to not step over the system containerd (if you have it installed)
# For that you can run:
# 	bin/containerd config default  > test.toml
# And modify the `root`, `state` and `grpc.address` paths to use unexistant
# directories
# Furthermore, be sure to include sbin in the PATH. Some distros don't have
# sbin in the PATH for unprivileged users and can cause issues (like unable to
# find iptables binary). If you find an error when creating pods regarding missing
# binaries, it is probably this.
# Another option is to run this as root to have sbin in PATH.
sudo PATH=/path/to/runc:$PATH bin/containerd --config test.toml
```

Clone kubernetes repo and start Kubernetes with local-up-cluster.sh, make sure
to use Kubernetes >= 1.19:
```
# Make sure the endpoints match the values you configured for containerd
# `grpc.address`
export CONTAINER_RUNTIME_ENDPOINT=unix:///run/cricontainerd/containerd.sock
export IMAGE_SERVICE_ENDPOINT=unix:///run/cricontainerd/containerd.sock
export CONTAINER_RUNTIME=remote
export EVICTION_HARD="memory.available<100Mi,nodefs.available<2%,nodefs.inodesFree<2%"

hack/local-up-cluster.sh
```

Start Seccomp Notify
```
kubectl apply -f deploy/seccompagent.yaml
```

Add a seccomp policy in /var/lib/kubelet/seccomp/notify.json:
```
{
  "listenerPath": "/run/seccomp-agent.socket",
  "listenerMetadata": "MKDIR_TMPL=-{{.Namespace}}-{{.Pod}}-{{.Container}}\nEXEC_PATTERN=/bin/true\nEXEC_DURATION=2s\nMOUNT_PROC=true\nMOUNT_SYSFS=true",
   "architectures" : [
      "SCMP_ARCH_X86",
      "SCMP_ARCH_X32"
   ],
   "defaultAction" : "SCMP_ACT_ALLOW",
   "syscalls" : [
      {
         "action" : "SCMP_ACT_NOTIFY",
         "names" : [
            "openat",
            "open",
            "mkdir",
            "mount",
            "chmod",
            "execve"
         ]
      }
   ]
}
```

Start a new pod:
```
apiVersion: v1
kind: Pod
metadata:
  name: mynotifypod
spec:
  securityContext:
    seccompProfile:
      type: Localhost
      # By default this file is located here: /var/lib/kubelet/seccomp/notify.json
      localhostProfile: notify.json
  restartPolicy: Never
  containers:
  - name: container1
    image: busybox
    command: ["sh"]
    args: ["-c", "sleep infinity"]
```
