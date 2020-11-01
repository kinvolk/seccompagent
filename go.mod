module github.com/kinvolk/seccompagent

go 1.15

require (
	github.com/opencontainers/runtime-spec v1.0.2
	github.com/seccomp/libseccomp-golang v0.9.1
	golang.org/x/crypto v0.0.0-20200220183623-bac4c82f6975 // indirect
	golang.org/x/oauth2 v0.0.0-20190604053449-0f29369cfe45 // indirect
	golang.org/x/sys v0.0.0-20201101102859-da207088b7d1
	golang.org/x/time v0.0.0-20200630173020-3af7569d3a1e // indirect
	k8s.io/api v0.17.4
	k8s.io/apimachinery v0.17.4
	k8s.io/client-go v12.0.0+incompatible
	k8s.io/utils v0.0.0-20191114184206-e782cd3c129f // indirect
)

replace github.com/opencontainers/runtime-spec => github.com/kinvolk/runtime-spec v1.0.2-0.20201028165138-cdac3792831d

replace github.com/seccomp/libseccomp-golang => github.com/kinvolk/libseccomp-golang v0.9.2-0.20201015160038-2c3f37066e3b
