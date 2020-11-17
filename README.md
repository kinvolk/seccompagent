# Kinvolk Seccomp Agent

The Kinvolk Seccomp Agent is receiving seccomp file descriptors from container runtimes and handling system calls on behalf of the containers.
Its goal is to support different use cases:
- unprivileged container builds (procfs mounts with masked entries)
- support of safe mknod (e.g. /dev/null)

It is possible to write your own seccomp agent with a different behaviour by reusing the packages in the `pkg/` directory.
The Kinvolk Seccomp Agent is only about 100 lines of code. It relies on different packages:
- `pkg/agent`: listens on a unix socket to receive new seccomp file descriptors from the container runtime and associates a registry to them
- `pkg/handlers`: basic implementations of system call handlers, such as mkdir, mount...
- `pkg/kuberesolver`: allows users to assign a custom registry to the seccomp fd depending on the Kubernetes pod.
- `pkg/nsenter`: allows handlers implementations to execute code in different namespaces
- `pkg/readarg`: allows handlers implementations to dereference system call arguments.
- `pkg/registry`: a set of system call handlers associated to a seccomp file descriptor.

## Basic demo

* Run the Seccomp Agent with the "demo-basic" container resolver.
```
sudo ./seccompagent -resolver=demo-basic
```

Demo of mount in a container without `CAP_SYS_ADMIN`:
```
/ # mount -t proc proc root
/ # ls /root/self/cmdline
/root/self/cmdline
```

* Demo of overriding a `mkdir` path:
```
/ # mkdir /abc
/ # ls -1d /ab*
/abc-pid-4072889
```

* Demo of overriding a `chmod` error:
```
/ # chmod 777 /
chmod: /: Bad message
```

## Demo on Kubernetes

This demo shows that the Seccomp Agent can have different behaviour depending on the Kubernetes pod (in this case, the pod's namespace and name).

* Run containerd/cri with from the `alban_seccomp_demo` branch.

* Install a seccomp policy: `/var/lib/kubelet/seccomp/notify.json`
```
{
   "architectures" : [
      "SCMP_ARCH_X86",
      "SCMP_ARCH_X32"
   ],
   "defaultAction" : "SCMP_ACT_ALLOW",
   "listenerPath": "/run/seccomp-agent.socket",
   "listenerMetadata": "MKDIR_TMPL=-{{.Namespace}}-{{.Pod}}-{{.Container}}\nEXEC_PATTERN=/bin/true\nEXEC_DURATION=2s\nMOUNT_PROC=true",
   "syscalls" : [
      {
         "action" : "SCMP_ACT_NOTIFY",
         "names" : [
            "openat",
            "open",
            "mkdir",
            "mount",
	    "chmod"
         ]
      }
   ]
}
```

* Deploy the seccomp agent:
```
kubectl apply -f deploy/seccompagent.yaml
```

* Deploy a pod with the seccomp policy:
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

* Run commands in the pod:
```
$ kubectl exec -it mynotifypod -- /bin/sh
/ # mkdir /abc
/ # ls -1d /abc*
/abc-default-mynotifypod-TODO
/ # mount -t proc proc root
/ # mount|grep /root
proc on /root type proc (rw,relatime)
/ # time -f %E /bin/echo -n ""
0m 0.00s
/ # time -f %E /bin/true
0m 2.00s
```
