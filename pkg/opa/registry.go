package opa

import (
	"context"
	"fmt"
	"io/ioutil"
	"os"

	"github.com/kinvolk/seccompagent/pkg/handlers"
	"github.com/kinvolk/seccompagent/pkg/kuberesolver"
	"github.com/kinvolk/seccompagent/pkg/readarg"
	"github.com/kinvolk/seccompagent/pkg/registry"
	"github.com/open-policy-agent/opa/rego"
	libseccomp "github.com/seccomp/libseccomp-golang"
	log "github.com/sirupsen/logrus"
	"golang.org/x/sys/unix"
)

type OpaFilter struct {
	seccompFile *os.File
	podCtx      *kuberesolver.PodContext
}

func NewOpaFilter(podCtx *kuberesolver.PodContext) *OpaFilter {
	return &OpaFilter{
		podCtx: podCtx,
	}
}

func (f *OpaFilter) Name() (name string) {
	if f.seccompFile != nil {
		name = f.seccompFile.Name()
	}
	return
}

func (f *OpaFilter) ShortName() (name string) {
	if f.seccompFile != nil {
		name = fmt.Sprintf("%d", f.seccompFile.Fd())
	}
	return
}

func (f *OpaFilter) SetSeccompFile(file *os.File) {
	f.seccompFile = file
}

func (f *OpaFilter) SeccompFile() *os.File {
	return f.seccompFile
}

func (f *OpaFilter) AddHandler(syscallName string, h registry.HandlerFunc) {
}

func (f *OpaFilter) LookupHandler(syscallName string) (h registry.HandlerFunc, ok bool) {
	handler := func(filter registry.Filter, req *libseccomp.ScmpNotifReq) (result registry.HandlerResult) {
		result = registry.HandlerResult{Flags: libseccomp.NotifRespFlagContinue}

		memFile, err := readarg.OpenMem(req.Pid)
		if err != nil {
			return
		}
		defer memFile.Close()

		if err := filter.NotifIDValid(req); err != nil {
			return registry.HandlerResult{Intr: true}
		}

		fileName, err := readarg.ReadString(memFile, int64(req.Data.Args[0]))
		if err != nil {
			log.WithFields(log.Fields{
				"filter": filter.Name(),
				"pid":    req.Pid,
				"err":    err,
			}).Error("Cannot read argument")
			return
		}

		input := map[string]interface{}{
			"syscall": syscallName,
			"arg0":    fileName,
			"pod": map[string]interface{}{
				"namespace": f.podCtx.Namespace,
				"pod":       f.podCtx.Pod,
				"container": f.podCtx.Container,
			},
		}

		ctx := context.TODO()

		content, err := ioutil.ReadFile("/etc/seccomp-agent/example.rego")
		if err != nil {
			log.WithFields(log.Fields{
				"filename": fileName,
				"input":    input,
				"err":      err,
			}).Error("Cannot read example.rego")
			result = registry.HandlerResultErrno(unix.ENOSYS)
			return
		}
		module := string(content)

		opaMkdirQuery, err := rego.New(
			rego.Query("x = data.example.authz.handler_MkdirWithSuffix"),
			rego.Module("example.rego", module),
		).PrepareForEval(ctx)
		results, err := opaMkdirQuery.Eval(ctx, rego.EvalInput(input))
		log.WithFields(log.Fields{
			"filename":   fileName,
			"input":      input,
			"rego":       module,
			"opa-result": results,
			"err":        err,
		}).Trace("Results of mkdir evaluation")
		if err == nil && len(results) == 1 {
			if match, ok := results[0].Bindings["x"].(bool); ok && match {
				log.WithFields(log.Fields{
					"filename": fileName,
					"input":    input,
					"rego":     module,
					"err":      err,
				}).Trace("MkdirWithSuffix match!")
				result = handlers.MkdirWithSuffix(fmt.Sprintf("%s_%s_%s", f.podCtx.Namespace, f.podCtx.Pod, f.podCtx.Container))(filter, req)
				return
			}
		}

		//		opaMountQuery, err := rego.New(
		//			rego.Query("x = data.example.authz.handler_Mount"),
		//			rego.Module("example.rego", module),
		//		).PrepareForEval(ctx)
		//		results, err = opaMountQuery.Eval(ctx, rego.EvalInput(input))
		//		log.WithFields(log.Fields{
		//			"filename":   fileName,
		//			"input":      input,
		//			"rego":       module,
		//			"opa-result": results,
		//			"err":        err,
		//		}).Trace("Results of mount evaluation")
		//		if err == nil && len(results) == 1 {
		//			if match, ok := results[0].Bindings["x"].(bool); ok && match {
		//				log.WithFields(log.Fields{
		//					"filename": fileName,
		//					"input":    input,
		//					"rego":     module,
		//					"err":      err,
		//				}).Trace("Mount match!")
		//				allowedFilesystems := map[string]struct{}{"proc": struct{}{}}
		//				result = handlers.Mount(allowedFilesystems)(filter, req)
		//				return
		//			}
		//		}

		opaAllowQuery, err := rego.New(
			rego.Query("x = data.example.authz.allow"),
			rego.Module("example.rego", module),
		).PrepareForEval(ctx)
		if err != nil {
			log.WithFields(log.Fields{
				"filename": fileName,
				"input":    input,
				"rego":     module,
				"err":      err,
			}).Error("Cannot prepare rego for allow evaluation")
			result = registry.HandlerResultErrno(unix.ENOSYS)
			return
		}

		results, err = opaAllowQuery.Eval(ctx, rego.EvalInput(input))
		if err != nil {
			// Handle evaluation error.
			result = registry.HandlerResultErrno(unix.ENOSYS)
		} else if len(results) == 0 {
			// Handle undefined result.
			result = registry.HandlerResultErrno(unix.ENOSYS)
		} else if allowed, ok := results[0].Bindings["x"].(bool); !ok {
			// Handle unexpected result type.
			result = registry.HandlerResultErrno(unix.ENOSYS)
		} else {
			// Handle result/decision.
			// fmt.Printf("%+v", results) => [{Expressions:[true] Bindings:map[x:true]}]
			if allowed {
				result = registry.HandlerResultContinue()
			} else {
				result = registry.HandlerResultErrno(unix.EPERM)
			}
		}

		log.WithFields(log.Fields{
			"filename":   fileName,
			"input":      input,
			"opa-result": results,
			"result":     result,
		}).Trace("Opa query")

		return
	}
	return handler, true
}

func (f *OpaFilter) NotifIDValid(req *libseccomp.ScmpNotifReq) error {
	return libseccomp.NotifIDValid(libseccomp.ScmpFd(f.seccompFile.Fd()), req.ID)

}

func (f *OpaFilter) SetValue(key string, val interface{}) {
}

func (f *OpaFilter) Value(key string) interface{} {
	return nil
}
