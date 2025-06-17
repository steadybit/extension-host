// SPDX-License-Identifier: MIT
// SPDX-FileCopyrightText: 2024 Steadybit GmbH

package exthost

import (
	"context"
	"fmt"
	"github.com/steadybit/action-kit/go/action_kit_api/v2"
	"github.com/steadybit/action-kit/go/action_kit_commons/network"
	"github.com/steadybit/action-kit/go/action_kit_commons/runc"
	"github.com/steadybit/action-kit/go/action_kit_sdk"
	"github.com/steadybit/extension-kit/extbuild"
	"github.com/steadybit/extension-kit/extutil"
)

func NewNetworkBlockDnsContainerAction(r runc.Runc) action_kit_sdk.Action[NetworkActionState] {
	return &networkAction{
		runc:         r,
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
		Icon:        extutil.Ptr(dnsIcon),
		TargetSelection: &action_kit_api.TargetSelection{
			TargetType:         targetID,
			SelectionTemplates: &targetSelectionTemplates,
		},
		Technology:  extutil.Ptr("Linux Host"),
		Category:    extutil.Ptr("Network"),
		Kind:        action_kit_api.Attack,
		TimeControl: action_kit_api.TimeControlExternal,
		Parameters: []action_kit_api.ActionParameter{
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
				Name:         "dnsPort",
				Label:        "DNS Port",
				Description:  extutil.Ptr("dnsPort"),
				Type:         action_kit_api.Integer,
				DefaultValue: extutil.Ptr("53"),
				Required:     extutil.Ptr(true),
				Order:        extutil.Ptr(1),
				MinValue:     extutil.Ptr(1),
				MaxValue:     extutil.Ptr(65534),
			},
		},
	}
}

func blockDns() networkOptsProvider {
	return func(ctx context.Context, sidecar network.SidecarOpts, request action_kit_api.PrepareActionRequestBody) (network.Opts, action_kit_api.Messages, error) {
		_, err := CheckTargetHostname(request.Target.Attributes)
		if err != nil {
			return nil, nil, err
		}
		dnsPort := uint16(extutil.ToUInt(request.Config["dnsPort"]))

		return &network.BlackholeOpts{
			Filter: network.Filter{Include: network.NewNetWithPortRanges(network.NetAny, network.PortRange{From: dnsPort, To: dnsPort})},
		}, nil, nil
	}
}
