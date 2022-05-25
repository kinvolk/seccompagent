module github.com/kinvolk/seccompagent

go 1.15

require (
	github.com/falcosecurity/plugin-sdk-go v0.3.0
	github.com/gogo/protobuf v1.3.2 // indirect
	github.com/opencontainers/runc v1.1.0
	github.com/opencontainers/runtime-spec v1.0.3-0.20210326190908-1c3f411f0417
	github.com/seccomp/libseccomp-golang v0.9.2-0.20210429002308-3879420cc921
	github.com/sirupsen/logrus v1.8.1
	golang.org/x/crypto v0.0.0-20220314234659-1baeb1ce4c0b // indirect
	golang.org/x/net v0.0.0-20220127200216-cd36cc0744dd // indirect
	golang.org/x/sys v0.0.0-20220209214540-3681064d5158
	google.golang.org/genproto v0.0.0-20220216160803-4663080d8bc8 // indirect
	google.golang.org/grpc v1.44.0
	google.golang.org/protobuf v1.27.1
	k8s.io/api v0.20.4
	k8s.io/apimachinery v0.20.4
	k8s.io/client-go v0.20.4
)
