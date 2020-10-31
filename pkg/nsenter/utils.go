// +build linux

package nsenter

import (
	"encoding/base64"
	"encoding/json"
	"fmt"
	"os"
	"os/exec"
)

type Module interface {
	Run([]byte)
}

type RunFunc func([]byte)

var modules map[string]RunFunc

func RegisterModule(name string, f RunFunc) bool {
	if modules == nil {
		modules = map[string]RunFunc{}
	}
	modules[name] = f
	return true
}

// Init checks if the process has re-executed itself and must run a registered
// module. Init() needs to be called explicitely from main() to ensure it is
// called after all other init() functions.
func Init() {
	if len(os.Args) < 2 || os.Args[1] != "-init" {
		return
	}

	defer os.Exit(0)

	str := os.Getenv("_LIBNSENTER_COMMAND")
	if str == "" {
		fmt.Printf("Invalid call to init\n")
		os.Exit(1)
	}
	jsonBlob, err := base64.StdEncoding.DecodeString(str)
	if err != nil {
		fmt.Println("error:", err)
		return
	}

	type module struct {
		Module string `json:"module,omitempty"`
	}

	var m module
	err = json.Unmarshal(jsonBlob, &m)
	if err != nil {
		fmt.Println("error:", err)
		return
	}
	fmt.Printf("%+v\n", m)

	f, ok := modules[m.Module]
	if !ok {
		fmt.Printf("error: module %q not registered\n", m.Module)
		return
	}
	f(jsonBlob)
}

func Run(mntnspath string, i interface{}) error {
	fmt.Printf("Run.\n")

	b, err := json.Marshal(i)
	if err != nil {
		return fmt.Errorf("Unable to encode interface: %s", err)
	}

	cmd := exec.Command("/proc/self/exe", "-init")
	cmd.Env = append(cmd.Env, "_LIBNSENTER_INIT=1")
	cmd.Env = append(cmd.Env, "_LIBNSENTER_MNTNSPATH="+mntnspath)
	cmd.Env = append(cmd.Env, "_LIBNSENTER_COMMAND="+base64.StdEncoding.EncodeToString(b))

	stdoutStderr, err := cmd.CombinedOutput()
	if err != nil {
		return fmt.Errorf("Unable to start the init command: %s\n%s\n", err, stdoutStderr)
	}
	fmt.Printf("init command returned:\n<<<\n%s\n>>>\n", stdoutStderr)

	return nil
}
