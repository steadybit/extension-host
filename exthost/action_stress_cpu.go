/*
 * Copyright 2023 steadybit GmbH. All rights reserved.
 */

package exthost

import (
	"fmt"
	"github.com/pkg/errors"
	"github.com/steadybit/action-kit/go/action_kit_api/v2"
	"github.com/steadybit/action-kit/go/action_kit_commons/ociruntime"
	"github.com/steadybit/action-kit/go/action_kit_commons/stress"
	"github.com/steadybit/action-kit/go/action_kit_sdk"
	"github.com/steadybit/extension-kit/extbuild"
	"github.com/steadybit/extension-kit/extutil"
	"time"
)

func NewStressCpuAction(r ociruntime.OciRuntime) action_kit_sdk.Action[StressActionState] {
	return newStressAction(r, getStressCpuDescription, stressCpu)
}

func getStressCpuDescription() action_kit_api.ActionDescription {
	return action_kit_api.ActionDescription{
		Id:          fmt.Sprintf("%s.stress-cpu", BaseActionID),
		Label:       "Stress CPU",
		Description: "Generates CPU load for one or more cores.",
		Version:     extbuild.GetSemverVersionStringOrUnknown(),
		Icon:        new(stressCPUIcon),
		TargetSelection: new(action_kit_api.TargetSelection{
			// The target type this action is for
			TargetType: targetID,
			// You can provide a list of target templates to help the user select targets.
			// A template can be used to pre-fill a selection
			SelectionTemplates: &targetSelectionTemplates,
		}),
		Technology: new("Linux Host"),
		// Category for the targets to appear in
		Category: new("Resource"),

		// To clarify the purpose of the action, you can set a kind.
		//   Attack: Will cause harm to targets
		//   Check: Will perform checks on the targets
		//   LoadTest: Will perform load tests on the targets
		//   Other
		Kind: action_kit_api.Attack,

		// How the action is controlled over time.
		//   External: The agent takes care and calls stop then the time has passed. Requires a duration parameter. Use this when the duration is known in advance.
		//   Internal: The action has to implement the status endpoint to signal when the action is done. Use this when the duration is not known in advance.
		//   Instantaneous: The action is done immediately. Use this for actions that happen immediately, e.g. a reboot.
		TimeControl: action_kit_api.TimeControlExternal,

		// The parameters for the action
		Parameters: []action_kit_api.ActionParameter{
			{
				Name:         "cpuLoad",
				Label:        "Host CPU Load",
				Description:  new("How much CPU should be consumed?"),
				Type:         action_kit_api.ActionParameterTypePercentage,
				DefaultValue: new("80"),
				Required:     new(true),
				Order:        new(1),
				MinValue:     new(0),
				MaxValue:     new(100),
			},
			{
				Name:         "workers",
				Label:        "Host CPUs",
				Description:  new("How many workers should be used to stress the CPU?"),
				Type:         action_kit_api.ActionParameterTypeStressngWorkers,
				DefaultValue: new("0"),
				Required:     new(true),
				Order:        new(2),
			},
			{
				Name:         "duration",
				Label:        "Duration",
				Description:  new("How long should CPU be stressed?"),
				Type:         action_kit_api.ActionParameterTypeDuration,
				DefaultValue: new("30s"),
				Required:     new(true),
				Order:        new(3),
			},
		},
		Stop: new(action_kit_api.MutatingEndpointReference{}),
	}
}

func stressCpu(request action_kit_api.PrepareActionRequestBody) (stress.Opts, error) {
	duration := time.Duration(extutil.ToInt64(request.Config["duration"])) * time.Millisecond

	if duration < 1*time.Second {
		return stress.Opts{}, errors.New("duration must be greater / equal than 1s")
	}

	return stress.Opts{
		CpuWorkers: new(extutil.ToInt(request.Config["workers"])),
		CpuLoad:    extutil.ToInt(request.Config["cpuLoad"]),
		Timeout:    duration,
	}, nil
}
