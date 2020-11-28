// +build linux,cgo

package main

import (
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io/ioutil"
	"net"
	"os"
	"strings"

	"github.com/opencontainers/runc/libcontainer/seccomp"
	"github.com/opencontainers/runc/libcontainer/specconv"
	"github.com/opencontainers/runc/libcontainer/utils"
	"github.com/opencontainers/runtime-spec/specs-go"
	log "github.com/sirupsen/logrus"
	"golang.org/x/sys/unix"
)

var (
	paramSeccompFile string
	socketFile       string
	paramMetadata    string
	paramID          string
	logflags         string
)

func init() {
	flag.StringVar(&paramSeccompFile, "seccomp-policy", "/var/lib/kubelet/seccomp/default.json", "Seccomp Policy file")
	flag.StringVar(&socketFile, "socketfile", "/run/seccomp-agent.socket", "Socket file")
	flag.StringVar(&paramMetadata, "metadata", "", "Metadata to send to the seccomp agent")
	flag.StringVar(&paramID, "id", "", "Container ID to send to the seccomp agent")
	flag.StringVar(&logflags, "log", "info", "log level [trace,debug,info,warn,error,fatal,color,nocolor,json]")
}

func sendContainerProcessState(listenerPath string, state *specs.ContainerProcessState, fds ...int) error {
	conn, err := net.Dial("unix", listenerPath)
	if err != nil {
		return fmt.Errorf("cannot connect to %q: %v\n", listenerPath, err)
	}

	socket, err := conn.(*net.UnixConn).File()
	if err != nil {
		return fmt.Errorf("cannot get socket: %v\n", err)
	}
	defer socket.Close()

	b, err := json.Marshal(state)
	if err != nil {
		return fmt.Errorf("cannot marshall seccomp state: %v\n", err)
	}

	err = utils.SendFds(socket, b, fds...)
	if err != nil {
		return fmt.Errorf("cannot send seccomp fd to %s: %v\n", listenerPath, err)
	}

	return nil
}

func main() {
	flag.Parse()
	for _, v := range strings.Split(logflags, ",") {
		if v == "json" {
			log.SetFormatter(&log.JSONFormatter{})
		} else if v == "color" {
			log.SetFormatter(&log.TextFormatter{ForceColors: true})
		} else if v == "nocolor" {
			log.SetFormatter(&log.TextFormatter{DisableColors: true})
		} else if lvl, err := log.ParseLevel(v); err == nil {
			log.SetLevel(lvl)
		} else {
			fmt.Fprintf(os.Stderr, "Invalid log level: %s\n", err.Error())
			flag.Usage()
			os.Exit(1)
		}
	}
	if flag.NArg() == 0 {
		panic(errors.New("invalid command"))
	}

	buf, err := ioutil.ReadFile(paramSeccompFile)
	if err != nil {
		panic(fmt.Errorf("cannot read file %q: %s", paramSeccompFile, err))
	}

	seccompConfigOCI := &specs.LinuxSeccomp{}
	json.Unmarshal(buf, seccompConfigOCI)

	seccompConfig, err := specconv.SetupSeccomp(seccompConfigOCI)
	if err != nil {
		panic(fmt.Errorf("cannot convert seccomp policy from OCI format to libcontainer format: %s", err))
	}

	if err := unix.Prctl(unix.PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0); err != nil {
		panic(fmt.Errorf("cannot set nonewprivileges", err))
	}

	containerProcessState := &specs.ContainerProcessState{
		Version:   specs.Version,
		FdIndexes: map[specs.FdIndexKey]int{specs.SeccompFdIndexKey: 0},
		Pid:       os.Getpid(),
		Metadata:  paramMetadata,
		State: specs.State{
			Version:     specs.Version,
			ID:          paramID,
			Status:      specs.StateRunning,
			Pid:         os.Getpid(),
			Bundle:      "",
			Annotations: map[string]string{},
		},
	}
	seccompFd, err := seccomp.InitSeccomp(seccompConfig)
	if err != nil || seccompFd == -1 {
		panic(fmt.Errorf("cannot init seccomp: %s", err))
	}

	if err := sendContainerProcessState(socketFile,
		containerProcessState, int(seccompFd)); err != nil {
		panic(fmt.Errorf("cannot send message to seccomp agent: %s", err))
	}

	if err := unix.Exec(flag.Arg(0), flag.Args()[1:], os.Environ()); err != nil {
		panic(fmt.Errorf("cannot exec command", err))
	}
}
