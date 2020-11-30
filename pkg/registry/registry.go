package registry

import (
	"fmt"
	"os"

	specs "github.com/opencontainers/runtime-spec/specs-go"
	libseccomp "github.com/seccomp/libseccomp-golang"
	"golang.org/x/sys/unix"
)

type HandlerResult struct {
	Intr   bool
	ErrVal int32
	Val    uint64
	Flags  uint32
}

type ResolverFunc func(state *specs.ContainerProcessState) Filter
type HandlerFunc func(Filter, *libseccomp.ScmpNotifReq) HandlerResult

// Helper functions for handlers
func HandlerResultIntr() HandlerResult {
	return HandlerResult{Intr: true}
}
func HandlerResultContinue() HandlerResult {
	return HandlerResult{Flags: libseccomp.NotifRespFlagContinue}
}

func HandlerResultErrno(err error) HandlerResult {
	if err == nil {
		return HandlerResult{}
	}
	errno, ok := err.(unix.Errno)
	if !ok {
		return HandlerResult{ErrVal: int32(unix.ENOSYS), Val: ^uint64(0)}
	}
	if errno == 0 {
		return HandlerResult{}
	}
	return HandlerResult{ErrVal: int32(errno), Val: ^uint64(0)}
}
func HandlerResultSuccess() HandlerResult {
	return HandlerResult{}
}

// Filter contains a set of handlers for a specific seccomp filter
type Filter interface {
	Name() string
	ShortName() string

	SetSeccompFile(file *os.File)
	SeccompFile() *os.File

	NotifIDValid(*libseccomp.ScmpNotifReq) error

	AddHandler(string, HandlerFunc)
	LookupHandler(string) (HandlerFunc, bool)

	SetValue(key string, val interface{})
	Value(key string) interface{}
}

type SimpleFilter struct {
	seccompFile    *os.File
	syscallHandler map[string]HandlerFunc
	values         map[string]interface{}
}

func NewSimpleFilter() *SimpleFilter {
	return &SimpleFilter{
		syscallHandler: map[string]HandlerFunc{},
		values:         map[string]interface{}{},
	}
}

func (f *SimpleFilter) Name() (name string) {
	if f.seccompFile != nil {
		name = f.seccompFile.Name()
	}
	return
}

func (f *SimpleFilter) ShortName() (name string) {
	if f.seccompFile != nil {
		name = fmt.Sprintf("%d", f.seccompFile.Fd())
	}
	return
}

func (f *SimpleFilter) SetSeccompFile(file *os.File) {
	f.seccompFile = file
}

func (f *SimpleFilter) SeccompFile() *os.File {
	return f.seccompFile
}

func (f *SimpleFilter) AddHandler(syscallName string, h HandlerFunc) {
	f.syscallHandler[syscallName] = h
}
func (f *SimpleFilter) LookupHandler(syscallName string) (h HandlerFunc, ok bool) {
	h, ok = f.syscallHandler[syscallName]
	return
}

func (f *SimpleFilter) NotifIDValid(req *libseccomp.ScmpNotifReq) error {
	return libseccomp.NotifIDValid(libseccomp.ScmpFd(f.seccompFile.Fd()), req.ID)

}

func (f *SimpleFilter) SetValue(key string, val interface{}) {
	f.values[key] = val
}

func (f *SimpleFilter) Value(key string) interface{} {
	return f.values[key]
}
