// SPDX-License-Identifier: MIT
// SPDX-FileCopyrightText: 2024 Steadybit GmbH

package exthost

import (
	"context"
	"encoding/json"
	"fmt"
	"github.com/steadybit/action-kit/go/action_kit_api/v2"
	"github.com/steadybit/action-kit/go/action_kit_commons/network"
	"github.com/steadybit/action-kit/go/action_kit_commons/network/netfault"
	"github.com/steadybit/action-kit/go/action_kit_commons/ociruntime"
	"github.com/steadybit/action-kit/go/action_kit_sdk"
	"github.com/steadybit/extension-host/config"
	extension_kit "github.com/steadybit/extension-kit"
	"github.com/steadybit/extension-kit/extbuild"
	"github.com/steadybit/extension-kit/extutil"
	"net"
)

func NewNetworkBlackholeContainerAction(r ociruntime.OciRuntime) action_kit_sdk.Action[NetworkActionState] {
	return &networkAction{
		ociRuntime:   r,
		optsProvider: blackhole(r),
		optsDecoder:  blackholeDecode,
		description:  getNetworkBlackholeDescription(),
	}
}

func getNetworkBlackholeDescription() action_kit_api.ActionDescription {
	return action_kit_api.ActionDescription{
		Id:          fmt.Sprintf("%s.network_blackhole", BaseActionID),
		Label:       "Block Traffic",
		Description: "Blocks network traffic (incoming and outgoing).",
		Version:     extbuild.GetSemverVersionStringOrUnknown(),
		Icon:        new(blackHoleIcon),
		TargetSelection: &action_kit_api.TargetSelection{
			TargetType:         targetID,
			SelectionTemplates: &targetSelectionTemplates,
		},
		Technology:  new("Linux Host"),
		Category:    new("Network"),
		Kind:        action_kit_api.Attack,
		TimeControl: action_kit_api.TimeControlExternal,
		Parameters: append(commonNetworkParameters,
			action_kit_api.ActionParameter{
				Name:         "blockLocalhost",
				Label:        "Block Localhost Traffic",
				Description:  new("Also block matching traffic on the loopback interface (127.0.0.0/8, ::1), e.g. between two processes on the same host. Combine with the include restrictions above, otherwise all localhost traffic is blocked."),
				Type:         action_kit_api.ActionParameterTypeBoolean,
				DefaultValue: new("false"),
				Advanced:     new(true),
				Order:        new(106),
			},
		),
	}
}

func blackhole(r ociruntime.OciRuntime) networkOptsProvider {
	return func(ctx context.Context, sidecar netfault.SidecarOpts, request action_kit_api.PrepareActionRequestBody) (netfault.Opts, action_kit_api.Messages, error) {
		_, err := CheckTargetHostname(request.Target.Attributes)
		if err != nil {
			return nil, nil, err
		}

		var messages action_kit_api.Messages
		if usesCilium, err := netfault.HasCiliumIpRoutes(ctx, runner(r, sidecar)); err != nil {
			messages = append(messages, action_kit_api.Message{
				Level:   extutil.Ptr(action_kit_api.Warn),
				Message: fmt.Sprintf("Failed to check for Cilium routes: %v", err),
			})
		} else if usesCilium {
			return nil, nil, &extension_kit.ExtensionError{
				Title:  "'Block Traffic' on hosts with cilium installed is not supported.",
				Detail: new("Try replacing this attack with 'Drop Outgoing Traffic' with a loss of 100%. That affects only outgoing traffic, but should yield similar results."),
			}
		}

		filter, netMessages, err := mapToNetworkFilter(ctx, r, sidecar, request.Config, getRestrictedEndpoints(request))
		if err != nil {
			return nil, nil, err
		}
		messages = append(messages, netMessages...)

		blockLocalhost := extutil.ToBool(request.Config["blockLocalhost"])
		if blockLocalhost {
			filter.Exclude = append(filter.Exclude, localhostExcludesForOwnPorts()...)
		}

		return &netfault.BlackholeOpts{
			Filter:           filter,
			ExecutionContext: mapToExecutionContext(request),
			BlockLocalhost:   blockLocalhost,
		}, messages, nil
	}
}

func blackholeDecode(data json.RawMessage) (netfault.Opts, error) {
	var opts netfault.BlackholeOpts
	err := json.Unmarshal(data, &opts)
	return &opts, err
}

// localhostExcludesForOwnPorts keeps the extension reachable via localhost (e.g. an
// agent on the same host calling http://localhost:8085). The own-IP excludes leave
// out loopback addresses, which only matters once localhost traffic is blocked.
func localhostExcludesForOwnPorts() []network.NetWithPortRange {
	loopback := []net.IPNet{
		{IP: net.IPv4(127, 0, 0, 0), Mask: net.CIDRMask(8, 32)},
		{IP: net.IPv6loopback, Mask: net.CIDRMask(128, 128)},
	}
	ports := []network.PortRange{{From: config.Config.Port, To: config.Config.Port}}
	if config.Config.HealthPort > 0 && config.Config.HealthPort != config.Config.Port {
		ports = append(ports, network.PortRange{From: config.Config.HealthPort, To: config.Config.HealthPort})
	}
	excludes := network.NewNetWithPortRanges(loopback, ports...)
	for i := range excludes {
		excludes[i].Comment = "ext. port (localhost)"
	}
	return excludes
}
