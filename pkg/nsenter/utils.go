// +build linux

package nsenter

import (
	"encoding/base64"
	"encoding/json"
	"fmt"
	"os"
	"os/exec"
)

const stdioFdCount = 3

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
	fmt.Printf("init command returned: %s\n", stdoutStderr)

	return nil
}

type Module interface {
	Run([]byte)
}

var Modules map[string]Module = map[string]Module{}

func ResumeRun() {
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
	fmt.Printf("type: %T\n", Modules[m.Module])

	Modules[m.Module].Run(jsonBlob)
}
