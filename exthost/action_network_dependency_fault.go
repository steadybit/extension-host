// SPDX-License-Identifier: MIT
// SPDX-FileCopyrightText: 2026 Steadybit GmbH

package exthost

import (
	"context"
	"fmt"
	"net"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/opencontainers/runtime-spec/specs-go"
	"github.com/rs/zerolog/log"
	"github.com/steadybit/action-kit/go/action_kit_api/v2"
	"github.com/steadybit/action-kit/go/action_kit_commons/network"
	"github.com/steadybit/action-kit/go/action_kit_commons/network/nsrunner"
	"github.com/steadybit/action-kit/go/action_kit_commons/network/proxyfault"
	"github.com/steadybit/action-kit/go/action_kit_commons/ociruntime"
	"github.com/steadybit/action-kit/go/action_kit_sdk"
	"github.com/steadybit/extension-host/config"
	"github.com/steadybit/extension-kit/extbuild"
	"github.com/steadybit/extension-kit/extutil"
)

var _ action_kit_sdk.Action[DependencyFaultState] = (*dependencyFaultAction)(nil)
var _ action_kit_sdk.ActionWithStatus[DependencyFaultState] = (*dependencyFaultAction)(nil)
var _ action_kit_sdk.ActionWithStop[DependencyFaultState] = (*dependencyFaultAction)(nil)

// proxyHandle keeps the running proxy plus what's needed for an out-of-band
// revert (the same Opts reproduce the chain names; the sidecar reaches the
// target netns). Kept in memory only, like dns-inject.
type proxyHandle struct {
	proxy   proxyfault.Proxy
	opts    proxyfault.Opts
	sidecar ociruntime.LinuxProcessInfo
	id      string
}

var (
	dependencyFaultHandles     = map[string]*proxyHandle{}
	dependencyFaultHandlesLock sync.Mutex
)

type DependencyFaultState struct {
	ExecutionId string
}

type dependencyFaultAction struct {
	ociRuntime ociruntime.OciRuntime
}

func NewNetworkDependencyFaultAction(r ociruntime.OciRuntime) action_kit_sdk.Action[DependencyFaultState] {
	return &dependencyFaultAction{ociRuntime: r}
}

func (a *dependencyFaultAction) NewEmptyState() DependencyFaultState {
	return DependencyFaultState{}
}

func (a *dependencyFaultAction) Describe() action_kit_api.ActionDescription {
	return action_kit_api.ActionDescription{
		Id:          fmt.Sprintf("%s.network_dependency_fault", BaseActionID),
		Label:       "Fault Dependency Traffic",
		Description: "Transparently proxy the host's outgoing traffic to a dependency and inject a fault (latency, connection reset, or an HTTP error status) selected by hostname/SNI.",
		Version:     extbuild.GetSemverVersionStringOrUnknown(),
		TargetSelection: &action_kit_api.TargetSelection{
			TargetType:         targetID,
			SelectionTemplates: &targetSelectionTemplates,
		},
		Technology:  extutil.Ptr("Linux Host"),
		Category:    extutil.Ptr("Network"),
		Kind:        action_kit_api.Attack,
		TimeControl: action_kit_api.TimeControlExternal,
		Status: extutil.Ptr(action_kit_api.MutatingEndpointReferenceWithCallInterval{
			CallInterval: extutil.Ptr("2s"),
		}),
		Parameters: dependencyFaultParameters(),
	}
}

func (a *dependencyFaultAction) Prepare(ctx context.Context, state *DependencyFaultState, request action_kit_api.PrepareActionRequestBody) (*action_kit_api.PrepareResult, error) {
	if _, err := CheckTargetHostname(request.Target.Attributes); err != nil {
		return nil, err
	}

	opts, err := a.parseOpts(request)
	if err != nil {
		return nil, err
	}

	processInfo, err := ociruntime.ReadLinuxProcessInfo(ctx, 1, specs.NetworkNamespace)
	if err != nil {
		return nil, fmt.Errorf("failed to read init process info: %w", err)
	}

	sidecarId := fmt.Sprintf("%s-host", request.ExecutionId.String()[24:])
	proxy, err := proxyfault.NewProcess(ctx, a.ociRuntime, processInfo, sidecarId, opts)
	if err != nil {
		return nil, fmt.Errorf("failed to create transparent-proxy process: %w", err)
	}

	state.ExecutionId = request.ExecutionId.String()
	dependencyFaultHandlesLock.Lock()
	dependencyFaultHandles[state.ExecutionId] = &proxyHandle{proxy: proxy, opts: opts, sidecar: processInfo, id: sidecarId}
	dependencyFaultHandlesLock.Unlock()

	return &action_kit_api.PrepareResult{}, nil
}

func (a *dependencyFaultAction) Start(_ context.Context, state *DependencyFaultState) (*action_kit_api.StartResult, error) {
	handle, ok := getDependencyFaultHandle(state.ExecutionId)
	if !ok {
		return nil, fmt.Errorf("no transparent-proxy handle for execution %s", state.ExecutionId)
	}
	if err := handle.proxy.Start(); err != nil {
		return nil, fmt.Errorf("failed to start transparent-proxy: %w", err)
	}
	return &action_kit_api.StartResult{}, nil
}

func (a *dependencyFaultAction) Status(_ context.Context, state *DependencyFaultState) (*action_kit_api.StatusResult, error) {
	handle, ok := getDependencyFaultHandle(state.ExecutionId)
	if !ok {
		return &action_kit_api.StatusResult{Completed: true}, nil
	}
	if exited, err := handle.proxy.Exited(); exited {
		errMsg := "transparent-proxy exited unexpectedly"
		if err != nil {
			errMsg = fmt.Sprintf("transparent-proxy failed: %v", err)
		}
		return &action_kit_api.StatusResult{
			Completed: true,
			Error: &action_kit_api.ActionKitError{
				Title:  errMsg,
				Status: extutil.Ptr(action_kit_api.Errored),
			},
		}, nil
	}
	return &action_kit_api.StatusResult{Completed: false}, nil
}

func (a *dependencyFaultAction) Stop(ctx context.Context, state *DependencyFaultState) (*action_kit_api.StopResult, error) {
	handle, ok := getDependencyFaultHandle(state.ExecutionId)
	if !ok {
		return nil, nil
	}
	removeDependencyFaultHandle(state.ExecutionId)

	// Terminate the proxy: its in-process Guard tears down the interception.
	if err := handle.proxy.Stop(); err != nil {
		log.Warn().Err(err).Str("execution_id", state.ExecutionId).Msg("failed to stop transparent-proxy")
	}

	// Belt-and-suspenders: an idempotent out-of-band revert removes the rules
	// even if the proxy was killed before its Guard could run.
	runner := nsrunner.NewRuncRunner(a.ociRuntime, nsrunner.SidecarOpts{
		TargetProcess: handle.sidecar,
		Id:            handle.id,
		Env:           []string{"XTABLES_LOCKFILE=/tmp/xtables.lock"},
	})
	if err := proxyfault.Revert(ctx, runner, handle.opts); err != nil {
		log.Warn().Err(err).Str("execution_id", state.ExecutionId).Msg("out-of-band interception revert failed")
	}

	return nil, nil
}

// --- parameters & parsing ---

func dependencyFaultParameters() []action_kit_api.ActionParameter {
	return []action_kit_api.ActionParameter{
		{
			Name: "duration", Label: "Duration", Description: extutil.Ptr("How long to inject the fault."),
			Type: action_kit_api.ActionParameterTypeDuration, DefaultValue: extutil.Ptr("30s"), Required: extutil.Ptr(true), Order: extutil.Ptr(0),
		},
		{
			Name: "faultType", Label: "Fault Type", Description: extutil.Ptr("Which fault to inject on matching connections."),
			Type: action_kit_api.ActionParameterTypeString, DefaultValue: extutil.Ptr("latency"), Required: extutil.Ptr(true), Order: extutil.Ptr(1),
			Options: extutil.Ptr([]action_kit_api.ParameterOption{
				action_kit_api.ExplicitParameterOption{Label: "Latency", Value: "latency"},
				action_kit_api.ExplicitParameterOption{Label: "Connection Reset", Value: "reset"},
				action_kit_api.ExplicitParameterOption{Label: "HTTP Error Status", Value: "http_status"},
			}),
		},
		{
			Name: "networkLatency", Label: "Latency", Description: extutil.Ptr("Latency to add (for the Latency fault type)."),
			Type: action_kit_api.ActionParameterTypeDuration, DefaultValue: extutil.Ptr("500ms"), Required: extutil.Ptr(false), Order: extutil.Ptr(2),
		},
		{
			Name: "httpStatus", Label: "HTTP Status", Description: extutil.Ptr("HTTP status code to return (for the HTTP Error Status fault type, cleartext HTTP only)."),
			Type: action_kit_api.ActionParameterTypeInteger, DefaultValue: extutil.Ptr("503"), Required: extutil.Ptr(false), Order: extutil.Ptr(3),
		},
		{
			Name: "hostname", Label: "Dependency Hostnames", Description: extutil.Ptr("Apply the fault only to connections to these hosts (TLS SNI or HTTP Host, subdomain match). If empty, all intercepted connections are faulted."),
			Type: action_kit_api.ActionParameterTypeStringArray, Required: extutil.Ptr(false), Order: extutil.Ptr(4),
		},
		{
			Name: "ip", Label: "Dependency CIDRs", Description: extutil.Ptr("Intercept traffic destined for these IP CIDRs. Defaults to all destinations (0.0.0.0/0)."),
			Type: action_kit_api.ActionParameterTypeStringArray, Required: extutil.Ptr(false), Order: extutil.Ptr(5), Advanced: extutil.Ptr(true),
		},
		{
			Name: "port", Label: "Dependency Ports", Description: extutil.Ptr("Comma-separated destination ports to intercept."),
			Type: action_kit_api.ActionParameterTypeString, DefaultValue: extutil.Ptr("80,443"), Required: extutil.Ptr(false), Order: extutil.Ptr(6), Advanced: extutil.Ptr(true),
		},
		{
			Name: "excludeIp", Label: "Exclude CIDRs", Description: extutil.Ptr("Never intercept traffic to these CIDRs (in addition to the automatically protected agent/extension endpoints)."),
			Type: action_kit_api.ActionParameterTypeStringArray, Required: extutil.Ptr(false), Order: extutil.Ptr(7), Advanced: extutil.Ptr(true),
		},
	}
}

func (a *dependencyFaultAction) parseOpts(request action_kit_api.PrepareActionRequestBody) (proxyfault.Opts, error) {
	cfg := request.Config

	ports, err := parsePortsList(extutil.ToString(cfg["port"]))
	if err != nil {
		return proxyfault.Opts{}, err
	}

	includeCIDRs, err := parseCIDRList(extutil.ToStringArray(cfg["ip"]))
	if err != nil {
		return proxyfault.Opts{}, fmt.Errorf("invalid dependency CIDR: %w", err)
	}
	if len(includeCIDRs) == 0 {
		_, all, _ := net.ParseCIDR("0.0.0.0/0")
		includeCIDRs = []net.IPNet{*all}
	}

	excludeCIDRs, err := a.buildExcludes(request)
	if err != nil {
		return proxyfault.Opts{}, err
	}

	fault, err := parseFault(cfg)
	if err != nil {
		return proxyfault.Opts{}, err
	}

	proxyPort, err := freeHostPort()
	if err != nil {
		return proxyfault.Opts{}, fmt.Errorf("could not allocate a proxy port: %w", err)
	}

	duration := time.Duration(extutil.ToInt64(cfg["duration"])) * time.Millisecond

	return proxyfault.Opts{
		ExecutionId:  request.ExecutionId.String()[24:],
		ProxyPort:    proxyPort,
		MaxDuration:  duration + 30*time.Second, // deadman if Stop never arrives
		IncludeCIDRs: includeCIDRs,
		ExcludeCIDRs: excludeCIDRs,
		Ports:        ports,
		Fault:        fault,
	}, nil
}

func parseFault(cfg map[string]any) (proxyfault.Fault, error) {
	hosts := extutil.ToStringArray(cfg["hostname"])
	switch extutil.ToString(cfg["faultType"]) {
	case "latency":
		return proxyfault.Fault{Hosts: hosts, Latency: time.Duration(extutil.ToInt64(cfg["networkLatency"])) * time.Millisecond}, nil
	case "reset":
		return proxyfault.Fault{Hosts: hosts, AbortProbability: 1.0}, nil
	case "http_status":
		status := int(extutil.ToInt64(cfg["httpStatus"]))
		if status < 100 || status > 599 {
			return proxyfault.Fault{}, fmt.Errorf("httpStatus must be within [100,599], got %d", status)
		}
		return proxyfault.Fault{Hosts: hosts, HTTPStatus: status}, nil
	default:
		return proxyfault.Fault{}, fmt.Errorf("unknown faultType %q", extutil.ToString(cfg["faultType"]))
	}
}

func (a *dependencyFaultAction) buildExcludes(request action_kit_api.PrepareActionRequestBody) ([]net.IPNet, error) {
	var nwps []network.NetWithPortRange
	restricted, err := toExcludes(getRestrictedEndpoints(request))
	if err != nil {
		return nil, err
	}
	nwps = append(nwps, restricted...)
	nwps = append(nwps, network.ComputeExcludesForOwnIpAndPorts(config.Config.Port, config.Config.HealthPort)...)

	out := make([]net.IPNet, 0, len(nwps))
	for _, n := range nwps {
		out = append(out, n.Net)
	}

	userExcludes, _ := network.ParseCIDRs(extutil.ToStringArray(request.Config["excludeIp"]))
	out = append(out, userExcludes...)
	return out, nil
}

func parsePortsList(s string) ([]uint16, error) {
	var out []uint16
	for _, p := range strings.Split(s, ",") {
		p = strings.TrimSpace(p)
		if p == "" {
			continue
		}
		n, err := strconv.ParseUint(p, 10, 16)
		if err != nil {
			return nil, fmt.Errorf("invalid port %q: %w", p, err)
		}
		out = append(out, uint16(n))
	}
	if len(out) == 0 {
		return nil, fmt.Errorf("at least one intercept port is required")
	}
	return out, nil
}

func parseCIDRList(items []string) ([]net.IPNet, error) {
	var out []net.IPNet
	for _, s := range items {
		s = strings.TrimSpace(s)
		if s == "" {
			continue
		}
		_, n, err := net.ParseCIDR(s)
		if err != nil {
			return nil, err
		}
		out = append(out, *n)
	}
	return out, nil
}

// freeHostPort finds an unused TCP port in the host network namespace (the
// extension runs with hostNetwork, so this is the namespace the proxy binds in).
func freeHostPort() (uint16, error) {
	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		return 0, err
	}
	defer func() { _ = l.Close() }()
	return uint16(l.Addr().(*net.TCPAddr).Port), nil
}

func getDependencyFaultHandle(executionId string) (*proxyHandle, bool) {
	dependencyFaultHandlesLock.Lock()
	defer dependencyFaultHandlesLock.Unlock()
	h, ok := dependencyFaultHandles[executionId]
	return h, ok
}

func removeDependencyFaultHandle(executionId string) {
	dependencyFaultHandlesLock.Lock()
	defer dependencyFaultHandlesLock.Unlock()
	delete(dependencyFaultHandles, executionId)
}
