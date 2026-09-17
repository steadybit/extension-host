// SPDX-License-Identifier: MIT
// SPDX-FileCopyrightText: 2026 Steadybit GmbH

package e2e

import (
	"compress/gzip"
	"fmt"
	"io"
	"net"
	"net/http"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/rs/zerolog/log"
	"github.com/steadybit/action-kit/go/action_kit_test/e2e"
	"github.com/steadybit/extension-host/exthost"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	coltracepb "go.opentelemetry.io/proto/otlp/collector/trace/v1"
	tracepb "go.opentelemetry.io/proto/otlp/trace/v1"
	"google.golang.org/protobuf/proto"
)

// otlpCollectorPort is the port the in-test OTLP receiver listens on. The
// extension reaches it from inside minikube via host.minikube.internal.
const otlpCollectorPort = 4318

// otlpCollector is a minimal OTLP/HTTP trace receiver standing in for the
// collector an operator would point the extension at.
type otlpCollector struct {
	server *http.Server

	mu    sync.Mutex
	spans []*tracepb.Span
}

func startOtlpCollector(t *testing.T, addr string) *otlpCollector {
	t.Helper()

	c := &otlpCollector{}
	mux := http.NewServeMux()
	mux.HandleFunc("/v1/traces", c.handleTraces)
	c.server = &http.Server{Addr: addr, Handler: mux}

	listener, err := net.Listen("tcp", addr)
	require.NoError(t, err, "failed to listen for OTLP traces on %s", addr)

	go func() {
		if err := c.server.Serve(listener); err != nil && err != http.ErrServerClosed {
			log.Error().Err(err).Msg("OTLP collector stopped unexpectedly")
		}
	}()

	return c
}

func (c *otlpCollector) handleTraces(w http.ResponseWriter, r *http.Request) {
	body, err := readPossiblyGzipped(r)
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}

	var req coltracepb.ExportTraceServiceRequest
	if err := proto.Unmarshal(body, &req); err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}

	c.mu.Lock()
	for _, rs := range req.GetResourceSpans() {
		for _, ss := range rs.GetScopeSpans() {
			c.spans = append(c.spans, ss.GetSpans()...)
		}
	}
	c.mu.Unlock()

	resp, err := proto.Marshal(&coltracepb.ExportTraceServiceResponse{})
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	w.Header().Set("Content-Type", "application/x-protobuf")
	_, _ = w.Write(resp)
}

func readPossiblyGzipped(r *http.Request) ([]byte, error) {
	if r.Header.Get("Content-Encoding") != "gzip" {
		return io.ReadAll(r.Body)
	}
	gz, err := gzip.NewReader(r.Body)
	if err != nil {
		return nil, err
	}
	defer func() { _ = gz.Close() }()
	return io.ReadAll(gz)
}

func (c *otlpCollector) received() []*tracepb.Span {
	c.mu.Lock()
	defer c.mu.Unlock()
	return append([]*tracepb.Span(nil), c.spans...)
}

func (c *otlpCollector) reset() {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.spans = nil
}

func (c *otlpCollector) close() {
	if err := c.server.Close(); err != nil {
		log.Error().Err(err).Msg("Failed to close OTLP collector")
	}
}

// otelExtraArgs configures the extension to export traces to the in-test
// collector. The short schedule delay keeps the batch processor flushing while
// the action runs, since the extension is not restarted between test cases.
func otelExtraArgs() []string {
	env := []struct{ name, value string }{
		{"OTEL_EXPORTER_OTLP_ENDPOINT", fmt.Sprintf("http://host.minikube.internal:%d", otlpCollectorPort)},
		{"OTEL_EXPORTER_OTLP_PROTOCOL", "http/protobuf"},
		{"OTEL_SERVICE_NAME", "extension-host"},
		{"OTEL_BSP_SCHEDULE_DELAY", "1000"},
	}

	var args []string
	for i, e := range env {
		idx := strconv.Itoa(i)
		// --set-string: helm would otherwise type OTEL_BSP_SCHEDULE_DELAY as an
		// integer, and a container env value must be a string.
		args = append(args,
			"--set-string", "extraEnv["+idx+"].name="+e.name,
			"--set-string", "extraEnv["+idx+"].value="+e.value,
		)
	}
	return args
}

// An attack is several separate calls from the agent — prepare, start, then
// stop on cancel — and the point of tracing the extension is that each of them
// is visible. The agent does not propagate a traceparent today, so these are
// independent traces rather than one; what this pins is that the whole action
// lifecycle is instrumented, not just the first call.
func testOtelTracing(collector *otlpCollector) func(*testing.T, *e2e.Minikube, *e2e.Extension) {
	return func(t *testing.T, m *e2e.Minikube, e *e2e.Extension) {
		collector.reset()

		config := map[string]any{
			"duration": 10000,
			"workers":  0,
			"cpuLoad":  50,
		}

		action, err := e.RunAction(exthost.BaseActionID+".stress-cpu", getTarget(m), config, nil)
		require.NoError(t, err)
		e2e.AssertProcessRunningInContainer(t, m, e.Pod, "extension", "stress-ng", true)
		require.NoError(t, action.Cancel())

		wanted := []string{"/prepare", "/start", "/stop"}
		seen := map[string]*tracepb.Span{}

		require.Eventually(t, func() bool {
			for _, span := range collector.received() {
				if span.GetKind() != tracepb.Span_SPAN_KIND_SERVER {
					continue
				}
				for _, suffix := range wanted {
					if strings.HasSuffix(span.GetName(), suffix) {
						seen[suffix] = span
					}
				}
			}
			return len(seen) == len(wanted)
		}, 30*time.Second, 500*time.Millisecond,
			"expected exported server spans for the whole action lifecycle, got %v", spanNames(collector.received()))

		for _, suffix := range wanted {
			assert.True(t, strings.HasPrefix(seen[suffix].GetName(), "POST /"),
				"span for %s should be named by method and route, got %q", suffix, seen[suffix].GetName())
		}

		requireAllSidecarsCleanedUp(t, m, e)
	}
}

func spanNames(spans []*tracepb.Span) []string {
	names := make([]string, 0, len(spans))
	for _, s := range spans {
		names = append(names, s.GetName())
	}
	return names
}
