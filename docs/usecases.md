---
title: Use cases
weight: 10
description: >
  Use cases for the Seccomp Agent.
---

There are several use cases for using a Seccomp Agent.

## Mounting procfs in unprivileged containers

An unprivileged Kubernetes pod might want to use
[RootlessKit](https://github.com/rootless-containers/rootlesskit). There is one
step that is difficult in this setup: [mounting procfs in a unprivileged user
namespace](https://kinvolk.io/blog/2018/04/towards-unprivileged-container-builds/#the-exception-of-procfs-and-sysfs).
This is because Kubernetes pods are normally running with a masked procfs (see
[AllowedProcMountTypes](https://kubernetes.io/docs/concepts/policy/pod-security-policy/#allowedprocmounttypes)
in the Pod Security Policy documentation).

To avoid running a pod with `ProcMountType=UnmaskedProcMount` (which could be a
security issue), users can run a seccomp agent to capture the `mount` system
call and perform the procfs mount in the inner container in the seccomp agent
on behalf of the container.  This allows users to use RootlessKit and still
keep the security of masked procfs mount.

## Support for a subset of device mknod

A VPN container might need `/dev/net/tun` but cannot create the device without
`CAP_MKNOD`. Giving this capability to the container could be risky: the
container would be able to abuse the mknod call to get access to disks such as
`/dev/sda`.

The alternative could be to keep the container without `CAP_MKNOD` and add a
seccomp filter on `mknod` to let the Seccomp Agent run `mknod()` on behalf of
the container,

## Rootless Containers without /etc/subuid (`subuidless`)

The goal of subuidless is to allow running containers without /etc/subuid,
which isn't good fit for shared environments.

See:
https://github.com/rootless-containers/subuidless

## Accelerator for slirp4netns (`bypass4netns`)

When using slirp4netns as a networking solution for rootless containers, the
performance impact can be big. However, by capturing the `connect` call and
handling it in the seccomp agent, we avoid the performance impact: the network
traffic is no longer routed through a userspace process.

See:
https://github.com/rootless-containers/bypass4netns

## Emulating privileged sysctl

TODO

## Detection and reporting of unusual behavior with system calls

TODO

## Error injections (Chaos Engineering)

The Seccomp policy could include a scenario defining which system calls to make
fail.
