// SPDX-License-Identifier: MIT
// SPDX-FileCopyrightText: 2024 Steadybit GmbH

package exthost

import (
	"context"
	"fmt"
	"github.com/steadybit/action-kit/go/action_kit_api/v2"
	"github.com/steadybit/action-kit/go/action_kit_commons/network"
	"github.com/steadybit/action-kit/go/action_kit_commons/network/netfault"
	"github.com/steadybit/action-kit/go/action_kit_commons/ociruntime"
	"github.com/steadybit/action-kit/go/action_kit_sdk"
	"github.com/steadybit/extension-kit/extbuild"
	"github.com/steadybit/extension-kit/extutil"
)

func NewNetworkBlockDnsContainerAction(r ociruntime.OciRuntime) action_kit_sdk.Action[NetworkActionState] {
	return &networkAction{
		ociRuntime:   r,
		optsProvider: blockDns(),
		optsDecoder:  blackholeDecode,
		description:  getNetworkBlockDnsDescription(),
	}
}

func getNetworkBlockDnsDescription() action_kit_api.ActionDescription {
	return action_kit_api.ActionDescription{
		Id:          fmt.Sprintf("%s.network_block_dns", BaseActionID),
		Label:       "Block DNS",
		Description: "Blocks access to DNS servers",
		Version:     extbuild.GetSemverVersionStringOrUnknown(),
		Icon:        new(dnsIcon),
		TargetSelection: &action_kit_api.TargetSelection{
			TargetType:         targetID,
			SelectionTemplates: &targetSelectionTemplates,
		},
		Technology:  new("Linux Host"),
		Category:    new("Network"),
		Kind:        action_kit_api.Attack,
		TimeControl: action_kit_api.TimeControlExternal,
		Parameters: []action_kit_api.ActionParameter{
			{
				Name:         "duration",
				Label:        "Duration",
				Description:  new("How long should the network be affected?"),
				Type:         action_kit_api.ActionParameterTypeDuration,
				DefaultValue: new("30s"),
				Required:     new(true),
				Order:        new(0),
			},
			{
				Name:         "dnsPort",
				Label:        "DNS Port",
				Description:  new("Port number used for DNS queries (typically 53)"),
				Type:         action_kit_api.ActionParameterTypeInteger,
				DefaultValue: new("53"),
				Required:     new(true),
				Order:        new(1),
				MinValue:     new(1),
				MaxValue:     new(65534),
			},
		},
	}
}

func blockDns() networkOptsProvider {
	return func(ctx context.Context, sidecar netfault.SidecarOpts, request action_kit_api.PrepareActionRequestBody) (netfault.Opts, action_kit_api.Messages, error) {
		_, err := CheckTargetHostname(request.Target.Attributes)
		if err != nil {
			return nil, nil, err
		}
		dnsPort := uint16(extutil.ToUInt(request.Config["dnsPort"]))

		return &netfault.BlackholeOpts{
			Filter:           netfault.Filter{Include: network.NewNetWithPortRanges(network.NetAny, network.PortRange{From: dnsPort, To: dnsPort})},
			ExecutionContext: mapToExecutionContext(request),
		}, nil, nil
	}
}
