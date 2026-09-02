// SPDX-License-Identifier: MIT
// SPDX-FileCopyrightText: 2026 Steadybit GmbH

package exthost

import (
	"context"
	"net"
	"testing"
	"time"

	"github.com/opencontainers/runtime-spec/specs-go"
	"github.com/steadybit/action-kit/go/action_kit_api/v2"
	"github.com/steadybit/action-kit/go/action_kit_commons/network/proxyfault"
	"github.com/steadybit/action-kit/go/action_kit_commons/ociruntime"
	"github.com/steadybit/action-kit/go/action_kit_sdk"
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
