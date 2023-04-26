// Copyright 2023 G-Research
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package prometheus

import (
	"strconv"
	"time"

	libseccomp "github.com/seccomp/libseccomp-golang"
	log "github.com/sirupsen/logrus"

	"github.com/kinvolk/seccompagent/pkg/kuberesolver"
	"github.com/kinvolk/seccompagent/pkg/registry"

	"github.com/prometheus/client_golang/prometheus"
)

var requestsHistogram = prometheus.NewHistogramVec(
	prometheus.HistogramOpts{
		Namespace: "seccompagent",
		Name:      "request_duration_seconds",
		Help:      "Histogram of latencies for agent requests.",
		Buckets:   []float64{.05, .2, 1},
	},
	// We don't include pod to avoid high cardinality in the labels.
	[]string{"namespace", "syscall", "status"})

func init() {
	prometheus.Register(requestsHistogram)
}

func UpdateMetrics(podCtx *kuberesolver.PodContext) func(h registry.HandlerFunc) registry.HandlerFunc {
	return func(h registry.HandlerFunc) registry.HandlerFunc {
		return func(fd libseccomp.ScmpFd, req *libseccomp.ScmpNotifReq) registry.HandlerResult {

			start := time.Now()

			syscallName, err := req.Data.Syscall.GetName()
			if err != nil {
				log.WithFields(log.Fields{
					"fd":  fd,
					"req": req,
					"err": err,
				}).Error("Error in decoding syscall")
			}

			r := h(fd, req)

			elapsed := time.Now().Sub(start)
			status := strconv.Itoa(int(r.ErrVal))
			requestsHistogram.With(
				prometheus.Labels{
					"namespace": podCtx.Namespace,
					"syscall":   syscallName,
					"status":    status}).Observe(float64(elapsed))

			return r
		}
	}
}
