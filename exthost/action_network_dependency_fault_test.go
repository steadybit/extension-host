// SPDX-License-Identifier: MIT
// SPDX-FileCopyrightText: 2026 Steadybit GmbH

package exthost

import (
	"context"
	"net"
	"os"
	"testing"
	"time"

	"github.com/opencontainers/runtime-spec/specs-go"
	"github.com/steadybit/action-kit/go/action_kit_api/v2"
	"github.com/steadybit/action-kit/go/action_kit_commons/network/proxyfault"
	"github.com/steadybit/action-kit/go/action_kit_commons/ociruntime"
	"github.com/steadybit/action-kit/go/action_kit_sdk"
	"github.com/steadybit/extension-host/config"
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

func Test_parsePortsList(t *testing.T) {
	ports, err := parsePortsList("80, 443 ,8080")
	require.NoError(t, err)
	assert.Equal(t, []uint16{80, 443, 8080}, ports)

	_, err = parsePortsList("")
	assert.Error(t, err, "empty port list is an error")

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
	md := formatDependencyStatsMarkdown(s)
	assert.Contains(t, md, "Connections matched:** 10")
	assert.Contains(t, md, "Connections faulted:** 6")
	assert.Contains(t, md, "api.example.com")
	assert.Contains(t, md, "cdn.example.com")
	assert.NotContains(t, md, "No matching connections")

	empty := formatDependencyStatsMarkdown(proxyfault.Snapshot{})
	assert.Contains(t, empty, "No matching connections", "zero-match snapshot shows the hint")
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
	for _, want := range []string{"duration", "l7", "hostname", "percentage", "ip", "port", "excludeIp", "networkInterface"} {
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
	assert.Nil(t, dependencyStatsMessages(stubProxy{}))

	// A snapshot => one message tagged for the widget.
	msgs := dependencyStatsMessages(metricsProxy{snap: proxyfault.Snapshot{ConnectionsMatched: 3}, ok: true})
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
	if err := os.WriteFile(certPath, []byte("CERT-PEM"), 0600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(keyPath, []byte("KEY-PEM"), 0600); err != nil {
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
	assert.Equal(t, "80", httpAbort.defaultPorts())

	withInterceptCA(t)

	ca, err = httpAbort.tlsInterceptCA([]uint16{443})
	require.NoError(t, err)
	require.NotNil(t, ca)
	assert.Equal(t, "CERT-PEM", string(ca.CertPEM))
	assert.Equal(t, "KEY-PEM", string(ca.KeyPEM))
	// 443 becomes a sensible default once the proxy can terminate it.
	assert.Equal(t, "80,443", httpAbort.defaultPorts())

	// Latency already works over HTTPS at L4, so it never asks to decrypt.
	lca, err := latency.tlsInterceptCA([]uint16{443})
	require.NoError(t, err)
	assert.Nil(t, lca)
	assert.Equal(t, "80,443", latency.defaultPorts())
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

	assert.Nil(t, (&dependencyFaultAction{spec: latencyFaultSpec}).hint())
}

func Test_formatDependencyStatsMarkdown_rejected(t *testing.T) {
	// A rejection is the "CA isn't trusted" diagnosis; without it the operator
	// only sees connections that matched but were never faulted.
	md := formatDependencyStatsMarkdown(proxyfault.Snapshot{
		ConnectionsMatched:   2,
		ConnectionsFaulted:   0,
		TLSInterceptRejected: 2,
	})
	assert.Contains(t, md, "rejected the injected certificate")
	assert.Contains(t, md, "trust the configured CA")

	// Nothing rejected: no scary note.
	md = formatDependencyStatsMarkdown(proxyfault.Snapshot{ConnectionsMatched: 1, ConnectionsFaulted: 1})
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
