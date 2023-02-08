module github.com/kinvolk/seccompagent

go 1.15

require (
	github.com/falcosecurity/plugin-sdk-go v0.4.0
	github.com/inspektor-gadget/inspektor-gadget v0.12.1
	github.com/opencontainers/runc v1.1.0
	github.com/opencontainers/runtime-spec v1.0.3-0.20210326190908-1c3f411f0417
	github.com/seccomp/libseccomp-golang v0.9.2-0.20210429002308-3879420cc921
	github.com/sirupsen/logrus v1.8.1
	golang.org/x/sys v0.0.0-20220928140112-f11e5e49a4ec
	google.golang.org/grpc v1.47.0
	google.golang.org/protobuf v1.28.0
	k8s.io/api v0.25.4
	k8s.io/apimachinery v0.25.4
	k8s.io/client-go v0.25.4
)
