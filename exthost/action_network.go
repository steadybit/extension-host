// SPDX-License-Identifier: MIT
// SPDX-FileCopyrightText: 2023 Steadybit GmbH

package exthost

import (
	"context"
	"encoding/json"
	"fmt"
	"github.com/google/uuid"
	"github.com/rs/zerolog/log"
	"github.com/steadybit/action-kit/go/action_kit_api/v2"
	"github.com/steadybit/action-kit/go/action_kit_commons/network"
	"github.com/steadybit/action-kit/go/action_kit_commons/runc"
	"github.com/steadybit/action-kit/go/action_kit_sdk"
	"github.com/steadybit/extension-host/config"
	"github.com/steadybit/extension-kit"
	"github.com/steadybit/extension-kit/extutil"
	"net"
)

type networkOptsProvider func(ctx context.Context, sidecar network.SidecarOpts, request action_kit_api.PrepareActionRequestBody) (network.Opts, error)

type networkOptsDecoder func(data json.RawMessage) (network.Opts, error)

type networkAction struct {
	runc         runc.Runc
	description  action_kit_api.ActionDescription
	optsProvider networkOptsProvider
	optsDecoder  networkOptsDecoder
}

type NetworkActionState struct {
	ExecutionId uuid.UUID
	NetworkOpts json.RawMessage
	Sidecar     network.SidecarOpts
}

// Make sure networkAction implements all required interfaces
var _ action_kit_sdk.Action[NetworkActionState] = (*networkAction)(nil)
var _ action_kit_sdk.ActionWithStop[NetworkActionState] = (*networkAction)(nil)

var commonNetworkParameters = []action_kit_api.ActionParameter{
	{
		Name:         "duration",
		Label:        "Duration",
		Description:  extutil.Ptr("How long should the network be affected?"),
		Type:         action_kit_api.Duration,
		DefaultValue: extutil.Ptr("30s"),
		Required:     extutil.Ptr(true),
		Order:        extutil.Ptr(0),
	},
	{
		Name:         "hostname",
		Label:        "Hostname",
		Description:  extutil.Ptr("Restrict to/from which hosts the traffic is affected."),
		Type:         action_kit_api.StringArray,
		DefaultValue: extutil.Ptr(""),
		Advanced:     extutil.Ptr(true),
		Order:        extutil.Ptr(101),
	},
	{
		Name:         "ip",
		Label:        "IP Address",
		Description:  extutil.Ptr("Restrict to/from which IP addresses the traffic is affected."),
		Type:         action_kit_api.StringArray,
		DefaultValue: extutil.Ptr(""),
		Advanced:     extutil.Ptr(true),
		Order:        extutil.Ptr(102),
	},
	{
		Name:         "port",
		Label:        "Ports",
		Description:  extutil.Ptr("Restrict to/from which ports the traffic is affected."),
		Type:         action_kit_api.StringArray,
		DefaultValue: extutil.Ptr(""),
		Advanced:     extutil.Ptr(true),
		Order:        extutil.Ptr(103),
	},
}

func (a *networkAction) NewEmptyState() NetworkActionState {
	return NetworkActionState{}
}

func (a *networkAction) Describe() action_kit_api.ActionDescription {
	return a.description
}

func (a *networkAction) Prepare(ctx context.Context, state *NetworkActionState, request action_kit_api.PrepareActionRequestBody) (*action_kit_api.PrepareResult, error) {
	_, err := CheckTargetHostname(request.Target.Attributes)
	if err != nil {
		return nil, err
	}

	initProcess, err := runc.ReadLinuxProcessInfo(ctx, 1)
	if err != nil {
		return nil, extension_kit.ToError("Failed to prepare network settings.", err)
	}
	state.Sidecar = network.SidecarOpts{
		TargetProcess: initProcess,
		IdSuffix:      "host",
		ImagePath:     "/",
	}

	opts, err := a.optsProvider(ctx, state.Sidecar, request)
	if err != nil {
		return nil, extension_kit.ToError("Failed to prepare network settings.", err)
	}

	rawOpts, err := json.Marshal(opts)
	if err != nil {
		return nil, extension_kit.ToError("Failed to serialize network settings.", err)
	}

	state.NetworkOpts = rawOpts
	return nil, nil
}

func (a *networkAction) Start(ctx context.Context, state *NetworkActionState) (*action_kit_api.StartResult, error) {
	opts, err := a.optsDecoder(state.NetworkOpts)
	if err != nil {
		return nil, extension_kit.ToError("Failed to deserialize network settings.", err)
	}

	if err != nil {
		return nil, extension_kit.ToError("Failed to get hostname.", err)
	}
	err = network.Apply(ctx, a.runc, state.Sidecar, opts)
	if err != nil {
		return nil, extension_kit.ToError("Failed to apply network settings.", err)
	}

	return &action_kit_api.StartResult{
		Messages: extutil.Ptr([]action_kit_api.Message{
			{
				Level:   extutil.Ptr(action_kit_api.Info),
				Message: opts.String(),
			},
		}),
	}, nil

}

func (a *networkAction) Stop(ctx context.Context, state *NetworkActionState) (*action_kit_api.StopResult, error) {
	opts, err := a.optsDecoder(state.NetworkOpts)
	if err != nil {
		return nil, extension_kit.ToError("Failed to deserialize network settings.", err)
	}

	err = network.Revert(ctx, a.runc, state.Sidecar, opts)
	if err != nil {
		return nil, extension_kit.ToError("Failed to revert network settings.", err)
	}

	return nil, nil
}

func parsePortRanges(raw []string) ([]network.PortRange, error) {
	if raw == nil {
		return nil, nil
	}

	var ranges []network.PortRange

	for _, r := range raw {
		if len(r) == 0 {
			continue
		}
		parsed, err := network.ParsePortRange(r)
		if err != nil {
			return nil, err
		}
		ranges = append(ranges, parsed)
	}

	return ranges, nil
}

func mapToNetworkFilter(ctx context.Context, r runc.Runc, sidecar network.SidecarOpts, actionConfig map[string]interface{}, restrictedEndpoints []action_kit_api.RestrictedEndpoint) (network.Filter, error) {
	toResolve := append(
		extutil.ToStringArray(actionConfig["ip"]),
		extutil.ToStringArray(actionConfig["hostname"])...,
	)

	dig := network.HostnameResolver{Dig: &network.RuncDigRunner{Runc: r, Sidecar: sidecar}}

	includeIps, err := dig.Resolve(ctx, toResolve...)
	if err != nil {
		return network.Filter{}, err
	}
	//if no hostname/ip specified we affect all ips
	includeCidrs := network.NetAny
	if len(includeIps) > 0 {
		includeCidrs = network.IpToNet(includeIps)
	}

	portRanges, err := parsePortRanges(extutil.ToStringArray(actionConfig["port"]))
	if err != nil {
		return network.Filter{}, err
	}
	if len(portRanges) == 0 {
		//if no hostname/ip specified we affect all ports
		portRanges = []network.PortRange{network.PortRangeAny}
	}

	includes := network.NewNetWithPortRanges(includeCidrs, portRanges...)
	var excludes []network.NetWithPortRange

	for _, restrictedEndpoint := range restrictedEndpoints {
		log.Debug().Msgf("Adding restricted endpoint %s (%s) => %s:%d-%d", restrictedEndpoint.Name, restrictedEndpoint.Url, restrictedEndpoint.Cidr, restrictedEndpoint.PortMin, restrictedEndpoint.PortMax)
		_, cidr, err := net.ParseCIDR(restrictedEndpoint.Cidr)
		if err != nil {
			return network.Filter{}, fmt.Errorf("invalid cidr %s: %w", restrictedEndpoint.Cidr, err)
		}
		excludes = append(excludes, network.NewNetWithPortRanges([]net.IPNet{*cidr}, network.PortRange{From: uint16(restrictedEndpoint.PortMin), To: uint16(restrictedEndpoint.PortMax)})...)
	}

	ownIps := network.GetOwnIPs()
	ownPort := config.Config.Port
	ownHealthPort := config.Config.HealthPort
	nets := network.IpToNet(ownIps)

	log.Debug().Msgf("Adding own ip %s to exclude list (Ports %d and %d)", ownIps, ownPort, ownHealthPort)
	excludes = append(excludes, network.NewNetWithPortRanges(nets, network.PortRange{From: ownPort, To: ownPort})...)
	excludes = append(excludes, network.NewNetWithPortRanges(nets, network.PortRange{From: ownHealthPort, To: ownHealthPort})...)

	return network.Filter{
		Include: includes,
		Exclude: excludes,
	}, nil
}

func readNetworkInterfaces(ctx context.Context, r runc.Runc, sidecar network.SidecarOpts) ([]string, error) {
	ifcs, err := network.ListInterfaces(ctx, r, sidecar)
	if err != nil {
		return nil, err
	}

	var ifcNames []string
	for _, ifc := range ifcs {
		if ifc.HasFlag("UP") && !ifc.HasFlag("LOOPBACK") {
			ifcNames = append(ifcNames, ifc.Name)
		}
	}
	return ifcNames, nil
}
