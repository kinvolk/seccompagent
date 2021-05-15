package opa

import (
	"context"
	"fmt"
	"strings"
	"text/template"

	"github.com/kinvolk/seccompagent/pkg/handlers"
	"github.com/kinvolk/seccompagent/pkg/kuberesolver"
	"github.com/kinvolk/seccompagent/pkg/registry"
	"github.com/open-policy-agent/opa/rego"
	libseccomp "github.com/seccomp/libseccomp-golang"
	log "github.com/sirupsen/logrus"
	"golang.org/x/sys/unix"
)

func eval(filter registry.Filter, req *libseccomp.ScmpNotifReq,
	policy string, podCtx *kuberesolver.PodContext,
	syscallName string, args [6]string) (result registry.HandlerResult) {

	result = registry.HandlerResult{Flags: libseccomp.NotifRespFlagContinue}

	input := map[string]interface{}{
		"syscall": syscallName,
		"arg0":    args[0],
		"arg1":    args[1],
		"arg2":    args[2],
		"arg3":    args[3],
		"arg4":    args[4],
		"arg5":    args[5],
		"pod": map[string]interface{}{
			"namespace": podCtx.Namespace,
			"name":      podCtx.Pod,
			"container": podCtx.Container,
		},
	}

	ctx := context.TODO()
	opaActionsQuery, err := rego.New(
		rego.Query("actions = data.syscall.authz.action"),
		rego.Module("example.rego", policy),
	).PrepareForEval(ctx)
	if err != nil {
		log.WithFields(log.Fields{
			"arg":   args,
			"input": input,
			"rego":  policy,
			"err":   err,
		}).Error("Cannot prepare rego for allow evaluation")
		result = registry.HandlerResultErrno(unix.ENOSYS)
		return
	}

	results, err := opaActionsQuery.Eval(ctx, rego.EvalInput(input))
	if err != nil {
		log.WithFields(log.Fields{
			"syscall": syscallName,
			"args":    args,
			"rego":    policy,
			"input":   input,
			"err":     err,
		}).Error("OPA evaluation error")

		result = registry.HandlerResultErrno(unix.ENOSYS)
		return
	}

	if len(results) == 0 {
		log.WithFields(log.Fields{
			"syscall": syscallName,
			"args":    args,
			"rego":    policy,
			"input":   input,
			"err":     err,
		}).Error("OPA undefined result")

		result = registry.HandlerResultErrno(unix.ENOSYS)
		return
	}

	actions, ok := results[0].Bindings["actions"].([]interface{})
	if !ok {
		log.WithFields(log.Fields{
			"syscall": syscallName,
			"args":    args,
			"rego":    policy,
			"results": results,
			"actions": fmt.Sprintf("actions=%T", results[0].Bindings["actions"]),
			"input":   input,
			"err":     err,
		}).Error("OPA unexpected result type")

		result = registry.HandlerResultErrno(unix.ENOSYS)
		return
	}
	if len(actions) == 0 {
		log.WithFields(log.Fields{
			"syscall": syscallName,
			"args":    args,
			"rego":    policy,
			"results": results,
			"input":   input,
			"err":     err,
		}).Error("OPA no actions found")

		result = registry.HandlerResultErrno(unix.ENOSYS)
		return
	}
	action, ok := actions[0].(map[string]interface{})
	if !ok {
		log.WithFields(log.Fields{
			"syscall": syscallName,
			"args":    args,
			"rego":    policy,
			"results": results,
			"input":   input,
			"err":     err,
		}).Error("OPA unexpected action type found")

		result = registry.HandlerResultErrno(unix.ENOSYS)
		return
	}

	// Handle result/decision.
	// fmt.Printf("%+v", results) => [{Expressions:[true] Bindings:map[x:true]}]
	if passthrough, ok := action["passthrough"]; ok && passthrough.(bool) {
		log.WithFields(log.Fields{
			"syscall": syscallName,
			"args":    args,
			"rego":    policy,
			"input":   input,
		}).Trace("OPA action: passthrough")

		result = registry.HandlerResultContinue()
		return
	}

	if errno, ok := action["errno"]; ok && errno != "" {
		log.WithFields(log.Fields{
			"syscall": syscallName,
			"args":    args,
			"rego":    policy,
			"input":   input,
			"errno":   errno,
		}).Trace("OPA action: errno")

		result = registry.HandlerResultErrno(unix.EPERM)
		return
	}

	if handler, ok := action["handler"]; ok && handler != "" {
		log.WithFields(log.Fields{
			"syscall": syscallName,
			"args":    args,
			"rego":    policy,
			"input":   input,
			"handler": handler,
		}).Trace("OPA action: handler")

		switch handler {
		case "mkdir":
			var suffix strings.Builder
			if tmplStr, ok := action["suffix"].(string); ok {
				tmpl, err := template.New("mkdirTmpl").Parse(tmplStr)
				if err == nil {
					err = tmpl.Execute(&suffix, podCtx)
					if err == nil {
						result = handlers.MkdirWithSuffix(suffix.String())(filter, req)
					} else {
						log.WithFields(log.Fields{
							"syscall": syscallName,
							"args":    args,
							"rego":    policy,
							"input":   input,
							"handler": handler,
							"tmpl":    tmplStr,
							"err":     err,
						}).Error("OPA: cannot execute template for mkdir suffix")

						result = registry.HandlerResultErrno(unix.ENOSYS)
					}
				} else {
					log.WithFields(log.Fields{
						"syscall": syscallName,
						"args":    args,
						"rego":    policy,
						"input":   input,
						"handler": handler,
						"tmpl":    tmplStr,
						"err":     err,
					}).Error("OPA: cannot parse template for mkdir suffix")
					result = registry.HandlerResultErrno(unix.ENOSYS)
				}
			} else {
				log.WithFields(log.Fields{
					"syscall": syscallName,
					"args":    args,
					"rego":    policy,
					"input":   input,
					"handler": handler,
				}).Error("OPA: mkdir suffix not found")
				result = registry.HandlerResultErrno(unix.ENOSYS)
			}
		case "mount":
			allowedFilesystems := map[string]struct{}{args[2]: struct{}{}}
			result = handlers.Mount(allowedFilesystems)(filter, req)
		default:
			result = registry.HandlerResultErrno(unix.ENOSYS)
		}
		return
	}

	result = registry.HandlerResultErrno(unix.ENOSYS)

	return
}
