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
Before you install the demo on k8s, please ensure all [the requirements](./docs/install.md) are satisfied.

This demo shows that the Seccomp Agent can have different behaviour depending on the Kubernetes pod (in this case, the pod's namespace and name).

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
  # For older versions of Kubernetes (this annotation was deprecated in
  # Kubernetes v1.19 and completely removed in v1.27):
  annotations:
    seccomp.security.alpha.kubernetes.io/pod: localhost/notify.json
spec:
  restartPolicy: Never
  securityContext:
    # /var/lib/kubelet/seccomp/notify.json
    seccompProfile:
      type: Localhost
      localhostProfile: notify.json
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

## Combining with user namespaces

By combining this with Kubernetes's user namespace support it is possible to
allow a user within a user namespace to perform some operations which would
otherwise be limited to host root.

One example is mounting other filesystem types. This is most useful combined
with user namespaces to allow mounting network file systems while a pod is
running. This is far safer than giving the container `privileged` access but
does expose more of the kernel to the pod, so you should consider your security
carefully.

There is a possibility a process could change its user namespace after making
the mount system call, which could result in a confusing state. To fix this the
seccomp notify policy should use the SECCOMP_FILTER_FLAG_WAIT_KILLABLE_RECV
flag, however this is [not yet available in
runc](https://github.com/opencontainers/runc/issues/3860) and requires Linux >=
5.19.

Configure a policy, similar to above, but with the following metadata:
```json
{
   "architectures" : [
      "SCMP_ARCH_X86",
      "SCMP_ARCH_X32"
   ],
   "defaultAction" : "SCMP_ACT_ALLOW",
   "listenerPath": "/run/seccomp-agent.socket",
   "listenerMetadata": "MOUNT_OTHER_FS_LIST=cifs\nMOUNT_NEED_CAP_ADMIN=true",
   "syscalls" : [
      {
         "action" : "SCMP_ACT_NOTIFY",
         "names" : [
            "mount"
         ]
      },
      {
         "action" : "SCMP_ACT_ALLOW",
         "names" : [
            "umount"
         ]
      }
   ]
}
```

(Policy cut down for sake of example, recommended to use a full policy that
additionally configures notify for mount and allows umount.)

This has currently been successfully tested with cifs. Other filesystem types
should work; NFS will need NFS client utilities installing within the container
*and* on the host (e.g. to make upcalls work).

* Deploy a pod with the seccomp policy and user namespaces:
```yaml
apiVersion: v1
kind: Pod
metadata:
  name: mynotifypod-userns
spec:
  restartPolicy: Never
  # Needs "UserNamespacesSupport" feature gate currently
  hostUsers: false
  securityContext:
    # /var/lib/kubelet/seccomp/notify.json
    seccompProfile:
      type: Localhost
      localhostProfile: notify.json
  containers:
  - name: container1
    image: alpine
    command: ["sh"]
    args: ["-c", "sleep infinity"]
    securityContext:
      capabilities:
        # This is safe combined with hostUsers: false
        add: [SYS_ADMIN]
```

* Run commands in the pod:
```shell
$ kubectl exec -it mynotifypod-userns -- /bin/sh
/ # mkdir /mnt
/ # mount -t cifs -o username=user,password=pass '//10.0.0.1/C' /mnt
/ # df -h /mnt
/mnt # df -h /mnt
Filesystem                Size      Used Available Use% Mounted on
//10.0.0.1/C           95.4G     85.3G     10.1G  89% /mnt
/ # ls /mnt
$Recycle.Bin               Documents and Settings     Program files
[...]
/ # sed -i 's!^\(nobody.*/\)false!\1sh!' /etc/passwd
/ # su nobody
/ $ mount -t cifs -o username=user,password=pass '//10.0.0.1/C' /mnt
mount: permission denied (are you root?)
```
