// SPDX-License-Identifier: MIT
// SPDX-FileCopyrightText: 2023 Steadybit GmbH

package exthost

import (
	"context"
	"encoding/json"
	"fmt"
	"github.com/steadybit/action-kit/go/action_kit_api/v2"
	networkutils "github.com/steadybit/action-kit/go/action_kit_commons/network"
	"github.com/steadybit/action-kit/go/action_kit_sdk"
	"github.com/steadybit/extension-kit/extbuild"
	"github.com/steadybit/extension-kit/extutil"
)

func NewNetworkBlackholeContainerAction() action_kit_sdk.Action[NetworkActionState] {
	return &networkAction{
		optsProvider: blackhole(),
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
		Icon:        extutil.Ptr(blackHoleIcon),
		TargetSelection: &action_kit_api.TargetSelection{
			TargetType:         TargetID,
			SelectionTemplates: &targetSelectionTemplates,
		},
		Category:    extutil.Ptr("network"),
		Kind:        action_kit_api.Attack,
		TimeControl: action_kit_api.TimeControlExternal,
		Parameters:  commonNetworkParameters,
	}
}

func blackhole() networkOptsProvider {
	return func(ctx context.Context, request action_kit_api.PrepareActionRequestBody) (networkutils.Opts, error) {
		_, err := CheckTargetHostname(request.Target.Attributes)
		if err != nil {
			return nil, err
		}

		filter, err := mapToNetworkFilter(ctx, request.Config, getRestrictedEndpoints(request))
		if err != nil {
			return nil, err
		}

		return &networkutils.BlackholeOpts{Filter: filter}, nil
	}
}

func blackholeDecode(data json.RawMessage) (networkutils.Opts, error) {
	var opts networkutils.BlackholeOpts
	err := json.Unmarshal(data, &opts)
	return &opts, err
}
