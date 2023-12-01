// SPDX-License-Identifier: MIT
// SPDX-FileCopyrightText: 2023 Steadybit GmbH

package exthost

import (
	"context"
	"fmt"
	"github.com/steadybit/action-kit/go/action_kit_api/v2"
	networkutils "github.com/steadybit/action-kit/go/action_kit_commons/network"
	"github.com/steadybit/action-kit/go/action_kit_sdk"
	"github.com/steadybit/extension-kit/extbuild"
	"github.com/steadybit/extension-kit/extutil"
)

func NewNetworkBlockDnsContainerAction() action_kit_sdk.Action[NetworkActionState] {
	return &networkAction{
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
			TargetType:         TargetID,
			SelectionTemplates: &targetSelectionTemplates,
		},
		Category:    extutil.Ptr("network"),
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
				Label:        "Network Dns",
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
	return func(ctx context.Context, request action_kit_api.PrepareActionRequestBody) (networkutils.Opts, error) {
		_, err := CheckTargetHostname(request.Target.Attributes)
		if err != nil {
			return nil, err
		}
		dnsPort := uint16(extutil.ToUInt(request.Config["dnsPort"]))

		return &networkutils.BlackholeOpts{
			Filter: networkutils.Filter{Include: networkutils.NewNetWithPortRanges(networkutils.NetAny, networkutils.PortRange{From: dnsPort, To: dnsPort})},
		}, nil
	}
}
