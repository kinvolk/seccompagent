module github.com/kinvolk/seccompagent

go 1.15

require (
	github.com/opencontainers/runc v0.0.0-00010101000000-000000000000
	github.com/opencontainers/runtime-spec v1.0.3-0.20200929063507-e6143ca7d51d
	github.com/seccomp/libseccomp-golang v0.9.1
	github.com/sirupsen/logrus v1.7.0
	golang.org/x/crypto v0.0.0-20200220183623-bac4c82f6975 // indirect
	golang.org/x/oauth2 v0.0.0-20190604053449-0f29369cfe45 // indirect
	golang.org/x/sys v0.0.0-20201107080550-4d91cf3a1aaf
	golang.org/x/time v0.0.0-20200630173020-3af7569d3a1e // indirect
	k8s.io/api v0.17.4
	k8s.io/apimachinery v0.17.4
	k8s.io/client-go v12.0.0+incompatible
	k8s.io/utils v0.0.0-20191114184206-e782cd3c129f // indirect
)

replace github.com/opencontainers/runtime-spec => github.com/kinvolk/runtime-spec v1.0.2-0.20201110202115-2755fc508653

replace github.com/seccomp/libseccomp-golang => github.com/kinvolk/libseccomp-golang v0.9.2-0.20201113182948-883917843313

replace github.com/opencontainers/runc => github.com/kinvolk/runc v0.1.1-0.20201126131201-5a620a897292
