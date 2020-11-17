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

Start containerd CRI:
```
sudo PATH=/path/to/runc:$PATH _output/containerd --config myconfig.toml
```

Start Kubernetes with local-up-cluster.sh
```
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
  # /var/lib/kubelet/seccomp/notify.json
  annotations:
    seccomp.security.alpha.kubernetes.io/pod: localhost/notify.json
spec:
  restartPolicy: Never
  containers:
  - name: container1
    image: busybox
    command: ["sh"]
    args: ["-c", "sleep infinity"]
```
