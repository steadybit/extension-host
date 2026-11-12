// SPDX-License-Identifier: MIT
// SPDX-FileCopyrightText: 2026 Steadybit GmbH

package exthost

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"math/big"
	"net"
	"os"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/opencontainers/runtime-spec/specs-go"
	"github.com/steadybit/action-kit/go/action_kit_api/v2"
	"github.com/steadybit/action-kit/go/action_kit_commons/network/proxyfault"
	"github.com/steadybit/action-kit/go/action_kit_commons/ociruntime"
	"github.com/steadybit/action-kit/go/action_kit_sdk"
	"github.com/steadybit/extension-host/config"
	"github.com/steadybit/extension-host/exthost/flags"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func Test_latencyFaultSpec_buildFault(t *testing.T) {
	f, err := latencyFaultSpec.buildFault(map[string]any{"delay": int64(500)})
	require.NoError(t, err)
	assert.Equal(t, 500*time.Millisecond, f.Latency)
	assert.False(t, f.Reset)
	assert.Zero(t, f.HTTPStatus)

	_, err = latencyFaultSpec.buildFault(map[string]any{"delay": int64(0)})
	assert.Error(t, err, "zero delay must be rejected")
}

func Test_httpAbortFaultSpec_buildFault(t *testing.T) {
	f, err := httpAbortFaultSpec.buildFault(map[string]any{
		"httpStatus":    int64(503),
		"responseBody":  "boom",
		"responseDelay": int64(100),
	})
	require.NoError(t, err)
	assert.Equal(t, 503, f.HTTPStatus)
	assert.Equal(t, "boom", f.HTTPBody)
	assert.Equal(t, 100*time.Millisecond, f.Latency, "response delay reuses the latency stage")

	_, err = httpAbortFaultSpec.buildFault(map[string]any{"httpStatus": int64(999)})
	assert.Error(t, err, "out-of-range status must be rejected")
}

func Test_resetFaultSpec_buildFault(t *testing.T) {
	f, err := resetFaultSpec.buildFault(map[string]any{})
	require.NoError(t, err)
	assert.True(t, f.Reset)
	assert.Zero(t, f.Latency)
	assert.Zero(t, f.HTTPStatus)
}

func Test_formatDependencyStatsMarkdown_requests(t *testing.T) {
	// One keep-alive connection carrying 10 cleartext HTTP requests, 4 faulted:
	// the connection counters say 1/1, only the request counters show 40%.
	md := formatDependencyStatsMarkdown(proxyfault.Snapshot{
		ConnectionsMatched: 1,
		ConnectionsFaulted: 1,
		RequestsMatched:    10,
		RequestsFaulted:    4,
		PerHost: map[string]proxyfault.HostStat{
			"api.example.com": {Matched: 1, Faulted: 1, RequestsMatched: 10, RequestsFaulted: 4},
		},
	}, proxyfault.Opts{Ports: []uint16{443}})
	// The request counters replace the connection ones in the summary.
	require.Contains(t, md, "### Interception\n"+
		"- **Intercepting:** ports 443 (localhost excluded)\n"+
		"- **Requests to a dependency hostname:** 10\n"+
		"- **Requests faulted:** 4 (40.0%)\n\n### What was done\n")
	require.NotContains(t, md, "Connections intercepted")
	require.NotContains(t, md, "Connections faulted")
	require.NotContains(t, md, "cleartext HTTP")
	require.Contains(t, md, "| api.example.com | 1 | 1 | 10 | 4 |")

	// No cleartext HTTP requests (HTTPS or other TCP only): no request section
	// and the table keeps its connection columns.
	md = formatDependencyStatsMarkdown(proxyfault.Snapshot{
		ConnectionsMatched: 1,
		ConnectionsFaulted: 1,
		PerHost:            map[string]proxyfault.HostStat{"api.example.com": {Matched: 1, Faulted: 1}},
	}, proxyfault.Opts{})
	require.NotContains(t, md, "Requests")
	require.Contains(t, md, "- **Connections faulted:** 1")
	require.Contains(t, md, "| api.example.com | 1 | 1 |\n")
}

func Test_parsePortsList(t *testing.T) {
	ports, err := parsePortsList("80, 443 ,8080")
	require.NoError(t, err)
	assert.Equal(t, []uint16{80, 443, 8080}, ports)

	ports, err = parsePortsList("")
	require.NoError(t, err)
	assert.Empty(t, ports, "empty means every port")

	_, err = parsePortsList("notaport")
	assert.Error(t, err)
}

func Test_parseCIDRArgs_and_filterIPv4(t *testing.T) {
	cidrs, err := parseCIDRArgs([]string{"10.0.0.0/8", " ", "192.168.1.1"})
	require.NoError(t, err)
	assert.Len(t, cidrs, 2, "blank entries are skipped, bare IPs accepted")

	_, err = parseCIDRArgs([]string{"not-a-cidr"})
	assert.Error(t, err)

	mixed, err := parseCIDRArgs([]string{"10.0.0.0/8", "fe80::/10"})
	require.NoError(t, err)
	v4 := filterIPv4CIDRs(mixed)
	assert.Len(t, v4, 1, "IPv6 CIDRs are dropped")
}

func Test_formatDependencyStatsMarkdown(t *testing.T) {
	s := proxyfault.Snapshot{
		ConnectionsMatched:    10,
		ConnectionsFaulted:    6,
		LatencyApplied:        4,
		HTTPResponsesInjected: 2,
		ConnectionsAborted:    0,
		ConnectionsProxied:    4,
		PerHost: map[string]proxyfault.HostStat{
			"api.example.com": {Matched: 7, Faulted: 5},
			"cdn.example.com": {Matched: 3, Faulted: 1},
		},
	}
	md := formatDependencyStatsMarkdown(s, proxyfault.Opts{Ports: []uint16{80, 443}})
	assert.Contains(t, md, "Intercepting:** ports 80, 443 (localhost excluded)")
	assert.Contains(t, md, "Connections intercepted:** 10")
	assert.Contains(t, md, "To a dependency hostname:** 10")
	assert.Contains(t, md, "Connections faulted:** 6")
	assert.Contains(t, md, "api.example.com")
	assert.Contains(t, md, "cdn.example.com")
	assert.NotContains(t, md, "No connections intercepted")

	empty := formatDependencyStatsMarkdown(proxyfault.Snapshot{}, proxyfault.Opts{})
	assert.Contains(t, empty, "Intercepting:** all TCP ports (localhost excluded)")
	assert.Contains(t, empty, "No connections intercepted", "zero-match snapshot shows the hint")

	// Traffic flows but nothing reaches the named dependencies: point at the
	// hostnames, not at the interception.
	other := formatDependencyStatsMarkdown(proxyfault.Snapshot{ConnectionsMatched: 5}, proxyfault.Opts{})
	assert.Contains(t, other, "none to the dependency hostnames yet")
}

func Test_interceptionMessages(t *testing.T) {
	hosts := proxyfault.Fault{Hosts: []string{"api.example.com"}}

	msgs := interceptionMessages(proxyfault.Opts{Ports: []uint16{80, 443}, Fault: hosts}, false)
	require.Len(t, msgs, 1)
	assert.Equal(t, "Intercepting ports 80, 443 (localhost excluded) of the host; only connections to api.example.com are faulted.", msgs[0].Message)

	msgs = interceptionMessages(proxyfault.Opts{Fault: hosts}, false)
	require.Len(t, msgs, 2)
	assert.Contains(t, msgs[0].Message, "Intercepting all TCP ports (localhost excluded)")
	assert.Contains(t, msgs[1].Message, "kubelet")
	assert.Contains(t, msgs[1].Message, "non-HTTP protocols")

	// HTTP response injection without a CA: HTTPS on any port is untouched.
	msgs = interceptionMessages(proxyfault.Opts{Fault: hosts}, true)
	require.Len(t, msgs, 2)
	assert.Equal(t, action_kit_api.Warn, *msgs[1].Level)
	assert.Contains(t, msgs[1].Message, "HTTPS passes through untouched")
}

func Test_interceptionMessages_localhost(t *testing.T) {
	hosts := proxyfault.Fault{Hosts: []string{"api.example.com"}}
	// Same localhost handling with and without ports.
	for _, ports := range [][]uint16{nil, {80, 443}} {
		msgs := interceptionMessages(proxyfault.Opts{Ports: ports, Fault: hosts, InterceptLoopback: true}, false)
		assert.Contains(t, msgs[0].Message, "(localhost included)")
		assert.Equal(t, action_kit_api.Warn, *msgs[1].Level)
		assert.Contains(t, msgs[1].Message, "existing localhost connections may be reset")
	}
}

func Test_dependency_attackLocalhostParameter(t *testing.T) {
	// Off by default, with a warning about the side effects, on every dependency
	// fault — and on the TCP reset, for its L7 mode.
	params := map[string][]action_kit_api.ActionParameter{
		"tcp reset": tcpResetParameters(),
	}
	for _, spec := range []dependencyFaultSpec{latencyFaultSpec, httpAbortFaultSpec} {
		params[spec.id] = (&dependencyFaultAction{spec: spec}).Describe().Parameters
	}
	for name, ps := range params {
		i := slices.IndexFunc(ps, func(p action_kit_api.ActionParameter) bool { return p.Name == "attackLocalhost" })
		require.NotEqual(t, -1, i, "%s: attackLocalhost missing", name)
		p := ps[i]
		assert.Equal(t, "false", *p.DefaultValue, name)
		assert.True(t, *p.Advanced, name)
		assert.Contains(t, *p.Description, "127.0.0.0/8", name)
		assert.Contains(t, *p.Description, "may be reset when the attack starts", name)
	}
}

func Test_dependencyFault_parseOpts_attackLocalhost(t *testing.T) {
	prevPort, prevHealth := config.Config.Port, config.Config.HealthPort
	t.Cleanup(func() { config.Config.Port, config.Config.HealthPort = prevPort, prevHealth })
	config.Config.Port, config.Config.HealthPort = 8085, 8081

	a := &dependencyFaultAction{spec: latencyFaultSpec}
	request := func(cfg map[string]interface{}) action_kit_api.PrepareActionRequestBody {
		cfg["hostname"] = []interface{}{"api.example.com"}
		cfg["delay"] = 500
		cfg["duration"] = 30000
		return action_kit_api.PrepareActionRequestBody{ExecutionId: uuid.New(), Config: cfg}
	}

	for _, ports := range []string{"", "80,443"} {
		opts, err := a.parseOpts(request(map[string]interface{}{"port": ports}))
		require.NoError(t, err)
		assert.False(t, opts.InterceptLoopback, "ports %q: localhost is excluded by default", ports)

		opts, err = a.parseOpts(request(map[string]interface{}{"port": ports, "attackLocalhost": true}))
		require.NoError(t, err)
		assert.True(t, opts.InterceptLoopback, "ports %q", ports)
		// The host's loopback carries the extension's own ports.
		assert.Equal(t, []uint16{8085, 8081}, opts.LoopbackExcludePorts, "ports %q", ports)
	}
}

func Test_l7ResetConfig(t *testing.T) {
	in := map[string]interface{}{"port": []interface{}{"80", "8080"}, "hostname": []interface{}{"api.example.com"}}
	out := l7ResetConfig(in)
	assert.Equal(t, "80,8080", out["port"])
	assert.Equal(t, in["hostname"], out["hostname"])
	assert.Equal(t, []interface{}{"80", "8080"}, in["port"], "the caller's config must not be mutated")

	// Empty means all ports, as in packet-level mode — not a hidden 80,443.
	for _, ports := range []interface{}{nil, []interface{}{}} {
		got := l7ResetConfig(map[string]interface{}{"port": ports})["port"]
		assert.Equal(t, "", got)
		parsed, err := parsePortsList(got.(string))
		require.NoError(t, err)
		assert.Empty(t, parsed)
	}
}

func Test_tcpResetParameters_shape(t *testing.T) {
	params := tcpResetParameters()
	byName := map[string]bool{}
	orders := map[int]bool{}
	for _, p := range params {
		byName[p.Name] = true
		if p.Order != nil {
			require.Falsef(t, orders[*p.Order], "duplicate order %d", *p.Order)
			orders[*p.Order] = true
		}
	}
	for _, want := range []string{"duration", "l7", "hostname", "percentage", "ip", "port", "excludeIp", "networkInterface", "attackLocalhost"} {
		assert.Truef(t, byName[want], "missing parameter %q", want)
	}
}

func Test_networkTcpReset_Describe(t *testing.T) {
	a := NewNetworkTcpResetAction(nil)
	d := a.Describe()
	assert.Equal(t, "Reset TCP/HTTP(s) Connection", d.Label)
	require.NotNil(t, d.Widgets)
	require.Len(t, *d.Widgets, 1, "the dependency-stats widget is declared")
}

func Test_networkTcpReset_Status_packetModeEmitsNote(t *testing.T) {
	a := NewNetworkTcpResetAction(nil).(action_kit_sdk.ActionWithStatus[NetworkTcpResetState])
	res, err := a.Status(context.Background(), &NetworkTcpResetState{L7: false})
	require.NoError(t, err)
	require.NotNil(t, res)
	assert.Nil(t, res.Error)
	assert.False(t, res.Completed)
	require.NotNil(t, res.Messages)
	require.Len(t, *res.Messages, 1)
	require.NotNil(t, (*res.Messages)[0].Type)
	assert.Equal(t, dependencyStatsMessageType, *(*res.Messages)[0].Type)
}

// --- handle lifecycle + overlap guard ---

type stubProxy struct{}

func (stubProxy) Start() error                         { return nil }
func (stubProxy) Stop() error                          { return nil }
func (stubProxy) Exited() (bool, error)                { return false, nil }
func (stubProxy) Metrics() (proxyfault.Snapshot, bool) { return proxyfault.Snapshot{}, false }

func netnsInfo(inode uint64) ociruntime.LinuxProcessInfo {
	return ociruntime.LinuxProcessInfo{
		Namespaces: []ociruntime.LinuxNamespace{{Type: specs.NetworkNamespace, Inode: inode}},
	}
}

func optsScope(t *testing.T, ports []uint16, cidr string) proxyfault.Opts {
	t.Helper()
	_, n, err := net.ParseCIDR(cidr)
	require.NoError(t, err)
	return proxyfault.Opts{Ports: ports, IncludeCIDRs: []net.IPNet{*n}}
}

func Test_networkNamespaceInode(t *testing.T) {
	assert.Equal(t, uint64(4242), networkNamespaceInode(netnsInfo(4242)))
	assert.Equal(t, uint64(0), networkNamespaceInode(ociruntime.LinuxProcessInfo{}), "no netns => 0")
}

func Test_portsOverlap_and_cidrsOverlap(t *testing.T) {
	assert.True(t, portsOverlap([]uint16{80, 443}, []uint16{443}))
	assert.False(t, portsOverlap([]uint16{80}, []uint16{443}))
	// No ports means every port, which overlaps anything.
	assert.True(t, portsOverlap(nil, []uint16{443}))
	assert.True(t, portsOverlap([]uint16{8080}, nil))

	_, a, _ := net.ParseCIDR("10.0.0.0/8")
	_, b, _ := net.ParseCIDR("10.1.2.0/24")
	_, c, _ := net.ParseCIDR("192.168.0.0/16")
	assert.True(t, cidrsOverlap([]net.IPNet{*a}, []net.IPNet{*b}), "subnet overlaps supernet")
	assert.False(t, cidrsOverlap([]net.IPNet{*a}, []net.IPNet{*c}))
}

func Test_scopesOverlap(t *testing.T) {
	existing := optsScope(t, []uint16{80, 443}, "10.0.0.0/8")
	// same ports + overlapping cidr => overlap
	assert.True(t, scopesOverlap(existing, []net.IPNet{*mustNet(t, "10.1.0.0/16")}, []uint16{443}))
	// disjoint ports => no overlap even if cidrs overlap
	assert.False(t, scopesOverlap(existing, []net.IPNet{*mustNet(t, "10.1.0.0/16")}, []uint16{8080}))
	// disjoint cidrs => no overlap even if ports overlap
	assert.False(t, scopesOverlap(existing, []net.IPNet{*mustNet(t, "192.168.0.0/16")}, []uint16{80}))
}

func mustNet(t *testing.T, cidr string) *net.IPNet {
	t.Helper()
	_, n, err := net.ParseCIDR(cidr)
	require.NoError(t, err)
	return n
}

func Test_dependencyFaultHandle_reserveStoreTake(t *testing.T) {
	id := "exec-" + t.Name()
	defer removeDependencyFaultHandle(id)

	reserved, conflict := reserveDependencyFaultHandle(id, netnsInfo(1001), optsScope(t, []uint16{80}, "10.0.0.0/8"))
	require.True(t, reserved)
	require.Empty(t, conflict)

	// Reservation is not yet a usable handle (proxy still nil).
	_, ok := getDependencyFaultHandle(id)
	assert.False(t, ok)

	// A second reserve for the same id is idempotent (not reserved, no conflict).
	reserved2, conflict2 := reserveDependencyFaultHandle(id, netnsInfo(1001), optsScope(t, []uint16{80}, "10.0.0.0/8"))
	assert.False(t, reserved2)
	assert.Empty(t, conflict2)

	// Fill it, then it becomes visible.
	storeDependencyFaultHandle(id, &proxyHandle{proxy: stubProxy{}, sidecar: netnsInfo(1001)})
	h, ok := getDependencyFaultHandle(id)
	require.True(t, ok)
	require.NotNil(t, h)

	// take removes it exactly once.
	_, took := takeDependencyFaultHandle(id)
	assert.True(t, took)
	_, took2 := takeDependencyFaultHandle(id)
	assert.False(t, took2)
}

func Test_reserveDependencyFaultHandle_conflictSameNetns(t *testing.T) {
	id1 := "exec1-" + t.Name()
	id2 := "exec2-" + t.Name()
	id3 := "exec3-" + t.Name()
	defer func() {
		removeDependencyFaultHandle(id1)
		removeDependencyFaultHandle(id2)
		removeDependencyFaultHandle(id3)
	}()

	scope := func() proxyfault.Opts { return optsScope(t, []uint16{80, 443}, "10.0.0.0/8") }

	r1, c1 := reserveDependencyFaultHandle(id1, netnsInfo(2001), scope())
	require.True(t, r1)
	require.Empty(t, c1)

	// Same netns + overlapping scope => conflict with id1.
	r2, c2 := reserveDependencyFaultHandle(id2, netnsInfo(2001), scope())
	assert.False(t, r2)
	assert.Equal(t, id1, c2)

	// Different netns + overlapping scope => allowed.
	r3, c3 := reserveDependencyFaultHandle(id3, netnsInfo(2002), scope())
	assert.True(t, r3)
	assert.Empty(t, c3)
}

type metricsProxy struct {
	stubProxy
	snap proxyfault.Snapshot
	ok   bool
}

func (p metricsProxy) Metrics() (proxyfault.Snapshot, bool) { return p.snap, p.ok }

func Test_dependencyStatsMessages(t *testing.T) {
	// No snapshot yet => no message (nil).
	assert.Nil(t, dependencyStatsMessages(stubProxy{}, proxyfault.Opts{}))

	// A snapshot => one message tagged for the widget.
	msgs := dependencyStatsMessages(metricsProxy{snap: proxyfault.Snapshot{ConnectionsMatched: 3}, ok: true}, proxyfault.Opts{})
	require.NotNil(t, msgs)
	require.Len(t, *msgs, 1)
	require.NotNil(t, (*msgs)[0].Type)
	assert.Equal(t, dependencyStatsMessageType, *(*msgs)[0].Type)
}

func Test_dependencyFault_constructors(t *testing.T) {
	for _, ctor := range []func() interface{ NewEmptyState() DependencyFaultState }{
		func() interface{ NewEmptyState() DependencyFaultState } {
			return NewNetworkDelayDependencyAction(nil).(interface {
				NewEmptyState() DependencyFaultState
			})
		},
		func() interface{ NewEmptyState() DependencyFaultState } {
			return NewNetworkHttpAbortDependencyAction(nil).(interface {
				NewEmptyState() DependencyFaultState
			})
		},
	} {
		a := ctor()
		require.NotNil(t, a)
		assert.Equal(t, DependencyFaultState{}, a.NewEmptyState())
	}

	// tcp reset empty state
	assert.Equal(t, NetworkTcpResetState{}, NewNetworkTcpResetAction(nil).NewEmptyState())
}

func Test_dependencyFault_hint(t *testing.T) {
	// The HTTP-abort action carries an action-level (global) hint warning that the
	// synthesized status/body applies to cleartext HTTP only.
	httpAbort := NewNetworkHttpAbortDependencyAction(nil).Describe()
	require.NotNil(t, httpAbort.Hint)
	assert.Equal(t, action_kit_api.HintWarning, httpAbort.Hint.Type)
	assert.Contains(t, httpAbort.Hint.Content, "cleartext HTTP")

	// The latency action has no such restriction, so it carries no hint.
	assert.Nil(t, NewNetworkDelayDependencyAction(nil).Describe().Hint)
}

// withInterceptCA points the global config at a CA for the duration of a test.
func withInterceptCA(t *testing.T) {
	t.Helper()
	prevCert, prevKey := config.Config.TLSInterceptCaCert, config.Config.TLSInterceptCaKey
	dir := t.TempDir()
	certPath, keyPath := dir+"/ca.crt", dir+"/ca.key"
	certPEM, keyPEM := testCAPEM(t)
	if err := os.WriteFile(certPath, certPEM, 0600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(keyPath, keyPEM, 0600); err != nil {
		t.Fatal(err)
	}
	config.Config.TLSInterceptCaCert = certPath
	config.Config.TLSInterceptCaKey = keyPath
	t.Cleanup(func() {
		config.Config.TLSInterceptCaCert, config.Config.TLSInterceptCaKey = prevCert, prevKey
	})
}

func Test_dependencyFault_tlsInterceptCA(t *testing.T) {
	httpAbort := &dependencyFaultAction{spec: httpAbortFaultSpec}
	latency := &dependencyFaultAction{spec: latencyFaultSpec}

	// Unconfigured: HTTPS is never decrypted.
	ca, err := httpAbort.tlsInterceptCA([]uint16{443})
	require.NoError(t, err)
	assert.Nil(t, ca)

	withInterceptCA(t)

	ca, err = httpAbort.tlsInterceptCA([]uint16{443})
	require.NoError(t, err)
	require.NotNil(t, ca)
	assert.Contains(t, string(ca.CertPEM), "BEGIN CERTIFICATE")
	assert.Contains(t, string(ca.KeyPEM), "PRIVATE KEY")

	// Latency decrypts too, to delay every HTTPS request.
	lca, err := latency.tlsInterceptCA([]uint16{443})
	require.NoError(t, err)
	assert.NotNil(t, lca)

	// A reset decrypts too, to reset each HTTPS request.
	rca, err := (&dependencyFaultAction{spec: resetFaultSpec}).tlsInterceptCA([]uint16{443})
	require.NoError(t, err)
	assert.NotNil(t, rca)
}

func Test_dependencyFault_percentageDescription(t *testing.T) {
	httpAbort := &dependencyFaultAction{spec: httpAbortFaultSpec}
	latency := &dependencyFaultAction{spec: latencyFaultSpec}

	require.NotContains(t, httpAbort.percentageDescription(), "HTTPS")
	require.Contains(t, latency.percentageDescription(), "per connection for HTTPS")
	require.Contains(t, tcpResetPercentageDescription(), "per connection for HTTPS")
	require.Contains(t, tcpResetPercentageDescription(), percentageScope(latencyFaultSpec))

	// With the CA, every attack reads HTTPS requests, so they are decided per
	// request.
	withInterceptCA(t)
	require.Contains(t, httpAbort.percentageDescription(), "HTTPS through the configured interception CA")
	require.Contains(t, latency.percentageDescription(), "HTTPS through the configured interception CA")
	require.Contains(t, tcpResetPercentageDescription(), "HTTPS through the configured interception CA")
	// The reset describes Percentage with the same sentence as the others.
	require.Contains(t, tcpResetPercentageDescription(), percentageScope(latencyFaultSpec))
}

func Test_tcpReset_hint(t *testing.T) {
	// Without a CA, L7 mode never decrypts, so there is nothing to warn about.
	require.Nil(t, NewNetworkTcpResetAction(nil).Describe().Hint)

	withInterceptCA(t)
	hint := NewNetworkTcpResetAction(nil).Describe().Hint
	require.NotNil(t, hint)
	assert.Contains(t, hint.Content, "L7 mode")
	assert.Contains(t, hint.Content, "every matched HTTPS connection is decrypted")
}

func Test_dependencyFault_hint_withInterceptCA(t *testing.T) {
	withInterceptCA(t)

	// The cleartext-only warning would now be wrong, so it is replaced by the
	// constraint that actually applies: the target must trust the CA.
	hint := (&dependencyFaultAction{spec: httpAbortFaultSpec}).hint()
	require.NotNil(t, hint)
	assert.Equal(t, action_kit_api.HintInfo, hint.Type)
	assert.Contains(t, hint.Content, "trust the configured CA")
	assert.NotContains(t, hint.Content, "cleartext HTTP only")
	// Requests that aren't faulted are forwarded, so the dependency's certificate
	// must verify too.
	assert.Contains(t, hint.Content, "can't verify the dependency's certificate")

	// Latency decrypts too, so the same constraint applies.
	assert.Equal(t, hint, (&dependencyFaultAction{spec: latencyFaultSpec}).hint())
}

func Test_formatDependencyStatsMarkdown_rejected(t *testing.T) {
	// A rejection is the "CA isn't trusted" diagnosis; without it the operator
	// only sees connections that matched but were never faulted.
	md := formatDependencyStatsMarkdown(proxyfault.Snapshot{
		ConnectionsMatched:   2,
		ConnectionsFaulted:   0,
		TLSInterceptRejected: 2,
	}, proxyfault.Opts{Ports: []uint16{443}})
	assert.Contains(t, md, "rejected the injected certificate")
	assert.Contains(t, md, "trust the configured CA")

	// Nothing rejected: no scary note.
	md = formatDependencyStatsMarkdown(proxyfault.Snapshot{ConnectionsMatched: 1, ConnectionsFaulted: 1}, proxyfault.Opts{Ports: []uint16{443}})
	assert.NotContains(t, md, "rejected the injected certificate")
}

// A CA that is configured but unreadable must fail loudly. Falling back to
// "cleartext only" would let HTTPS flow untouched while the operator believes
// it is being faulted — and would report a permissions problem as an
// unsupported-protocol one.
func Test_dependencyFault_tlsInterceptCA_unreadable(t *testing.T) {
	prevCert, prevKey := config.Config.TLSInterceptCaCert, config.Config.TLSInterceptCaKey
	t.Cleanup(func() {
		config.Config.TLSInterceptCaCert, config.Config.TLSInterceptCaKey = prevCert, prevKey
	})
	config.Config.TLSInterceptCaCert = t.TempDir() + "/missing.crt"
	config.Config.TLSInterceptCaKey = t.TempDir() + "/missing.key"

	ca, err := (&dependencyFaultAction{spec: httpAbortFaultSpec}).tlsInterceptCA([]uint16{443})
	require.Error(t, err)
	require.Nil(t, ca)
	require.Contains(t, err.Error(), "cannot read the configured TLS interception CA")
}

// The CA is only needed to decrypt 443. Demanding it for a cleartext-only scope
// would let a broken CA mount break port-80 attacks that never wanted it.
// Capturing every port includes HTTPS on any port, so the CA is needed.
func Test_dependencyFault_tlsInterceptCA_neededForAllPorts(t *testing.T) {
	withInterceptCA(t)
	ca, err := (&dependencyFaultAction{spec: httpAbortFaultSpec}).tlsInterceptCA(nil)
	require.NoError(t, err)
	require.NotNil(t, ca, "all ports must load the CA")
}

func Test_dependencyFault_tlsInterceptCA_notNeededForCleartextPorts(t *testing.T) {
	withInterceptCA(t)
	ca, err := (&dependencyFaultAction{spec: httpAbortFaultSpec}).tlsInterceptCA([]uint16{80})
	require.NoError(t, err)
	assert.Nil(t, ca, "port 80 only must not require the CA")
}

// An empty CA half is dropped silently further down the chain, which would
// leave HTTPS spliced through untouched while the UI claims interception is on.
func Test_dependencyFault_tlsInterceptCA_emptyIsAnError(t *testing.T) {
	prevCert, prevKey := config.Config.TLSInterceptCaCert, config.Config.TLSInterceptCaKey
	t.Cleanup(func() {
		config.Config.TLSInterceptCaCert, config.Config.TLSInterceptCaKey = prevCert, prevKey
	})
	dir := t.TempDir()
	certPath, keyPath := dir+"/empty.crt", dir+"/empty.key"
	require.NoError(t, os.WriteFile(certPath, nil, 0600))
	require.NoError(t, os.WriteFile(keyPath, []byte("KEY"), 0600))
	config.Config.TLSInterceptCaCert, config.Config.TLSInterceptCaKey = certPath, keyPath

	ca, err := (&dependencyFaultAction{spec: httpAbortFaultSpec}).tlsInterceptCA([]uint16{443})
	require.Error(t, err)
	require.Nil(t, ca)
	require.Contains(t, err.Error(), "empty")
}

// With a CA configured the description must not still tell the operator that
// HTTPS is unsupported, directly above a hint saying interception is on.
func Test_dependencyFault_description_withInterceptCA(t *testing.T) {
	withInterceptCA(t)
	d := (&dependencyFaultAction{spec: httpAbortFaultSpec}).description()
	require.NotContains(t, d, "Cleartext HTTP only")
	require.Contains(t, d, "trust")
}

// Readable and non-empty is not enough: the startup check only logs, so a CA
// whose halves do not match reaches the attack path. Catching it here names the
// problem instead of surfacing a bare proxy-startup failure.
func Test_dependencyFault_tlsInterceptCA_mismatchedPairIsAnError(t *testing.T) {
	prevCert, prevKey := config.Config.TLSInterceptCaCert, config.Config.TLSInterceptCaKey
	t.Cleanup(func() {
		config.Config.TLSInterceptCaCert, config.Config.TLSInterceptCaKey = prevCert, prevKey
	})
	dir := t.TempDir()
	certPath, keyPath := dir+"/ca.crt", dir+"/ca.key"
	require.NoError(t, os.WriteFile(certPath, []byte("-----BEGIN CERTIFICATE-----\nnot-a-cert\n-----END CERTIFICATE-----\n"), 0600))
	require.NoError(t, os.WriteFile(keyPath, []byte("-----BEGIN EC PRIVATE KEY-----\nnot-a-key\n-----END EC PRIVATE KEY-----\n"), 0600))
	config.Config.TLSInterceptCaCert, config.Config.TLSInterceptCaKey = certPath, keyPath

	ca, err := (&dependencyFaultAction{spec: httpAbortFaultSpec}).tlsInterceptCA([]uint16{443})
	require.Error(t, err)
	require.Nil(t, ca)
	require.Contains(t, err.Error(), "not a usable certificate/key pair")
}

// testCAPEM builds a genuine, minimal signing CA, since tlsInterceptCA now
// verifies the pair rather than only reading it.
func testCAPEM(t *testing.T) (certPEM, keyPEM []byte) {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)
	tmpl := &x509.Certificate{
		SerialNumber:          big.NewInt(1),
		Subject:               pkix.Name{CommonName: "Test Intercept CA"},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().Add(24 * time.Hour),
		IsCA:                  true,
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageCRLSign,
		BasicConstraintsValid: true,
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, key.Public(), key)
	require.NoError(t, err)
	keyDER, err := x509.MarshalECPrivateKey(key)
	require.NoError(t, err)
	return pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}),
		pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: keyDER})
}

func Test_dependencyFault_upstreamInsecureSkipVerifyParameter(t *testing.T) {
	has := func(spec dependencyFaultSpec) bool {
		return slices.ContainsFunc((&dependencyFaultAction{spec: spec}).Describe().Parameters, func(p action_kit_api.ActionParameter) bool {
			return p.Name == "upstreamInsecureSkipVerify"
		})
	}
	hasTcpReset := func() bool {
		return slices.ContainsFunc(NewNetworkTcpResetAction(nil).Describe().Parameters, func(p action_kit_api.ActionParameter) bool {
			return p.Name == "upstreamInsecureSkipVerify"
		})
	}
	// Without a CA nothing is decrypted, so there is no upstream TLS to verify.
	require.False(t, has(latencyFaultSpec))
	require.False(t, has(httpAbortFaultSpec))
	require.False(t, hasTcpReset())

	withInterceptCA(t)
	require.True(t, has(latencyFaultSpec))
	require.True(t, has(httpAbortFaultSpec))
	require.True(t, hasTcpReset())
}

func Test_dependencyFault_parseOpts_upstreamInsecureSkipVerify(t *testing.T) {
	a := &dependencyFaultAction{spec: latencyFaultSpec}
	request := func(cfg map[string]interface{}) action_kit_api.PrepareActionRequestBody {
		cfg["hostname"] = []interface{}{"api.example.com"}
		cfg["delay"] = 500
		cfg["duration"] = 30000
		return action_kit_api.PrepareActionRequestBody{ExecutionId: uuid.New(), Config: cfg}
	}

	// Without a CA the proxy never opens its own TLS connection.
	opts, err := a.parseOpts(request(map[string]interface{}{"upstreamInsecureSkipVerify": true}))
	require.NoError(t, err)
	require.False(t, opts.UpstreamInsecureSkipVerify)

	withInterceptCA(t)
	opts, err = a.parseOpts(request(map[string]interface{}{}))
	require.NoError(t, err)
	require.False(t, opts.UpstreamInsecureSkipVerify, "verified by default")

	opts, err = a.parseOpts(request(map[string]interface{}{"upstreamInsecureSkipVerify": true}))
	require.NoError(t, err)
	require.True(t, opts.UpstreamInsecureSkipVerify)

	// Strictly per experiment: the extension-wide setting doesn't turn it on.
	t.Setenv("STEADYBIT_EXTENSION_INSECURE_SKIP_VERIFY", "true")
	unset, err := a.parseOpts(request(map[string]interface{}{}))
	require.NoError(t, err)
	require.False(t, unset.UpstreamInsecureSkipVerify)

}

type upstreamErrorsProxy struct {
	errors int64
}

func (upstreamErrorsProxy) Start() error          { return nil }
func (upstreamErrorsProxy) Stop() error           { return nil }
func (upstreamErrorsProxy) Exited() (bool, error) { return false, nil }

func (p upstreamErrorsProxy) Metrics() (proxyfault.Snapshot, bool) {
	return proxyfault.Snapshot{UpstreamErrors: p.errors}, true
}

func Test_dependencyFault_Status_logsUpstreamErrorTipOnce(t *testing.T) {
	executionId := uuid.NewString()
	storeDependencyFaultHandle(executionId, &proxyHandle{
		proxy: upstreamErrorsProxy{errors: 2},
		opts:  proxyfault.Opts{TLSInterceptCA: &proxyfault.TLSInterceptCA{}},
	})
	t.Cleanup(func() { removeDependencyFaultHandle(executionId) })
	a := &dependencyFaultAction{spec: latencyFaultSpec}

	tips := func() int {
		res, err := a.Status(context.Background(), &DependencyFaultState{ExecutionId: executionId})
		require.NoError(t, err)
		n := 0
		for _, m := range *res.Messages {
			if strings.Contains(m.Message, "failed to forward") {
				n++
			}
		}
		return n
	}
	require.Equal(t, 1, tips())
	require.Equal(t, 0, tips(), "the tip is logged once per execution")
}

func Test_formatDependencyStatsMarkdown_upstreamErrors(t *testing.T) {
	md := formatDependencyStatsMarkdown(proxyfault.Snapshot{ConnectionsMatched: 1}, proxyfault.Opts{})
	require.NotContains(t, md, "Forwarding failed")

	md = formatDependencyStatsMarkdown(proxyfault.Snapshot{ConnectionsMatched: 1, UpstreamErrors: 2}, proxyfault.Opts{})
	require.Contains(t, md, "Forwarding failed 2 time(s).** The proxy couldn't connect to the destination._")

	md = formatDependencyStatsMarkdown(proxyfault.Snapshot{ConnectionsMatched: 1, UpstreamErrors: 2}, proxyfault.Opts{TLSInterceptCA: &proxyfault.TLSInterceptCA{}})
	require.Contains(t, md, "or couldn't verify the dependency's certificate")
}

func Test_dependencyFault_upstreamSkipVerifyNotInTrafficFilter(t *testing.T) {
	// The setting only exists with a CA; it doesn't filter traffic, so it stays
	// out of the Traffic Filter group.
	withInterceptCA(t)
	for _, spec := range []dependencyFaultSpec{latencyFaultSpec, httpAbortFaultSpec} {
		params := (&dependencyFaultAction{spec: spec}).Describe().Parameters
		i := slices.IndexFunc(params, func(p action_kit_api.ActionParameter) bool { return p.Name == flags.UpstreamSkipVerifyParameterName })
		require.NotEqual(t, -1, i, spec.id)
		require.Nil(t, params[i].Group, spec.id)
	}
}
