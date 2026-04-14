// Copyright 2025 steadybit GmbH. All rights reserved.

package exthost

import (
	"errors"
	"fmt"
	"github.com/steadybit/action-kit/go/action_kit_api/v2"
	"github.com/steadybit/action-kit/go/action_kit_commons/ociruntime"
	"github.com/steadybit/action-kit/go/action_kit_commons/stress"
	"github.com/steadybit/action-kit/go/action_kit_sdk"
	"github.com/steadybit/extension-kit/extbuild"
	"github.com/steadybit/extension-kit/extutil"
	"time"
)

type Mode string

const (
	ModeReadWriteAndFlush Mode = "read_write_and_flush"
	ModeReadWrite         Mode = "read_write"
	ModeFlush             Mode = "flush"
)

func NewStressIoAction(r ociruntime.OciRuntime) action_kit_sdk.Action[StressActionState] {
	return newStressAction(r, getStressIoDescription, stressIo)
}

// Describe returns the action description for the platform with all required information.
func getStressIoDescription() action_kit_api.ActionDescription {
	return action_kit_api.ActionDescription{
		Id:          fmt.Sprintf("%s.stress-io", BaseActionID),
		Label:       "Stress IO",
		Description: "Stresses IO on the host using read/write/flush operations for the given duration.",
		Version:     extbuild.GetSemverVersionStringOrUnknown(),
		Icon:        new(stressIOIcon),
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
				Name:         "mode",
				Label:        "Mode",
				Description:  new("How should the IO be stressed?"),
				Type:         action_kit_api.ActionParameterTypeString,
				DefaultValue: new(string(ModeReadWriteAndFlush)),
				Required:     new(true),
				Order:        new(0),
				MinValue:     new(1),
				MaxValue:     new(100),
				Options: &[]action_kit_api.ParameterOption{
					action_kit_api.ExplicitParameterOption{
						Label: "read/write and flush",
						Value: string(ModeReadWriteAndFlush),
					},
					action_kit_api.ExplicitParameterOption{
						Label: "read/write only",
						Value: string(ModeReadWrite),
					},
					action_kit_api.ExplicitParameterOption{
						Label: "flush only",
						Value: string(ModeFlush),
					},
				},
			},
			{
				Name:         "workers",
				Label:        "Workers",
				Description:  new("How many workers should continually write, read and remove temporary files?"),
				Type:         action_kit_api.ActionParameterTypeStressngWorkers,
				DefaultValue: new("0"),
				Required:     new(true),
				Order:        new(01),
			},
			{
				Name:         "duration",
				Label:        "Duration",
				Description:  new("How long should IO be stressed?"),
				Type:         action_kit_api.ActionParameterTypeDuration,
				DefaultValue: new("30s"),
				Required:     new(true),
				Order:        new(2),
			},
			{
				Name:         "path",
				Label:        "Path",
				Description:  new("Path where the IO should be inflicted"),
				Type:         action_kit_api.ActionParameterTypeString,
				DefaultValue: new("/"),
				Required:     new(true),
				Order:        new(3),
			},
			{
				Name:         "mbytes_per_worker",
				Label:        "MBytes to write",
				Description:  new("How many megabytes should be written per stress operation?"),
				Type:         action_kit_api.ActionParameterTypeInteger,
				DefaultValue: new("1024"),
				Required:     new(true),
				Order:        new(3),
				MinValue:     new(1),
			},
		},
		Stop: new(action_kit_api.MutatingEndpointReference{}),
	}
}

func stressIo(request action_kit_api.PrepareActionRequestBody) (stress.Opts, error) {
	workers := extutil.ToInt(request.Config["workers"])
	mode := extutil.ToString(request.Config["mode"])
	if mode == "" {
		mode = string(ModeReadWriteAndFlush)
	}

	duration := time.Duration(extutil.ToInt64(request.Config["duration"])) * time.Millisecond
	if duration < 1*time.Second {
		return stress.Opts{}, errors.New("duration must be greater / equal than 1s")
	}

	opts := stress.Opts{
		TempPath: extutil.ToString(request.Config["path"]),
		Timeout:  duration,
	}

	if mode == string(ModeReadWriteAndFlush) || mode == string(ModeReadWrite) {
		opts.HddWorkers = &workers
		opts.HddBytes = fmt.Sprintf("%dm", extutil.ToInt64(request.Config["mbytes_per_worker"]))
	}

	if mode == string(ModeReadWriteAndFlush) || mode == string(ModeFlush) {
		opts.IomixWorkers = &workers
	}

	return opts, nil
}
