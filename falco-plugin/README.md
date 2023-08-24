# seccompagent Falco plugin

## Build the plugin standalone

```
make -C falco-plugin
ls -l falco-plugin/libseccompagent.so
```

## Build a Falco container image with the plugin

```
export CONTAINER_REPO=${USER}test.azurecr.io/falco-with-seccompagent
export TAG=$CONTAINER_REPO:dev
docker build -f falco-plugin/Dockerfile -t $TAG .
docker push $TAG
```

## Run Falco with the plugin

Start Falco in a container as previously compiled:
```
docker run --rm -i -t \
           --privileged \
           -v /var/run/docker.sock:/host/var/run/docker.sock \
           -v /run/seccomp-agent-falco-plugin:/run/seccomp-agent-falco-plugin \
           -v /proc:/host/proc:ro \
           $TAG falco --modern-bpf
```

Start the Seccomp Agent:
```
sudo ./seccompagent -resolver=falco -log trace
```

Launch a container and run a command:
```
$ docker run --rm -it \
    --security-opt \
    seccomp=falco-plugin/seccomp-profile-demo.json \
    busybox
/ # mkdir /a
```

Falco logs the following:
```
Notice The seccomp agent detected a mkdir...
```
