/*
 * Copyright 2023 steadybit GmbH. All rights reserved.
 */

package exthost

import (
	"context"
	"errors"
	"fmt"
	"github.com/rs/zerolog/log"
	"github.com/steadybit/action-kit/go/action_kit_api/v2"
	"github.com/steadybit/action-kit/go/action_kit_sdk"
	"github.com/steadybit/extension-kit/extbuild"
	"github.com/steadybit/extension-kit/extutil"
	"strconv"
)

type stressCPUAction struct{}

// Make sure action implements all required interfaces
var (
	_ action_kit_sdk.Action[StressCPUActionState]           = (*stressCPUAction)(nil)
	_ action_kit_sdk.ActionWithStatus[StressCPUActionState] = (*stressCPUAction)(nil) // Optional, needed when the action needs a status method
	_ action_kit_sdk.ActionWithStop[StressCPUActionState]   = (*stressCPUAction)(nil) // Optional, needed when the action needs a stop method
)

type StressCPUActionState struct {
	stressNGArgs []string
}

func NewStressCPUAction() action_kit_sdk.Action[StressCPUActionState] {
	return &stressCPUAction{}
}

func (l *stressCPUAction) NewEmptyState() StressCPUActionState {
	return StressCPUActionState{}
}

// Describe returns the action description for the platform with all required information.
func (l *stressCPUAction) Describe() action_kit_api.ActionDescription {
	return action_kit_api.ActionDescription{
		Id:          fmt.Sprintf("%s.stressCPU", targetID),
		Label:       "Stress CPU",
		Description: "Generates CPU load for one or more cores.",
		Version:     extbuild.GetSemverVersionStringOrUnknown(),
		Icon:        extutil.Ptr(stressCPUIcon),
		TargetSelection: extutil.Ptr(action_kit_api.TargetSelection{
			// The target type this action is for
			TargetType: targetID,
			// You can provide a list of target templates to help the user select targets.
			// A template can be used to pre-fill a selection
			SelectionTemplates: extutil.Ptr([]action_kit_api.TargetSelectionTemplate{
				{
					Label: "by host name",
					Query: "host.name=\"\"",
				},
			}),
		}),
		// Category for the targets to appear in
		Category: extutil.Ptr("Resource"),

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
		TimeControl: action_kit_api.External,

		// The parameters for the action
		Parameters: []action_kit_api.ActionParameter{
			{
				Name:         "cpuLoad",
				Label:        "Host CPU Load",
				Description:  extutil.Ptr("How much CPU should be consumed?"),
				Type:         action_kit_api.Percentage,
				DefaultValue: extutil.Ptr("100"),
				Required:     extutil.Ptr(true),
				Order:        extutil.Ptr(1),
				MinValue:     extutil.Ptr(0),
				MaxValue:     extutil.Ptr(100),
			},
			{
				Name:         "workers",
				Label:        "Host CPUs",
				Description:  extutil.Ptr("How many workers should be used to stress the CPU?"),
				Type:         "stressng-workers",
				DefaultValue: extutil.Ptr("0"),
				Required:     extutil.Ptr(true),
				Order:        extutil.Ptr(2),
			},
			{
				Name:         "duration",
				Label:        "Duration",
				Description:  extutil.Ptr("How long should CPU be stressed?"),
				Type:         action_kit_api.Duration,
				DefaultValue: extutil.Ptr("30s"),
				Required:     extutil.Ptr(true),
				Order:        extutil.Ptr(3),
			},
		},
		Stop: extutil.Ptr(action_kit_api.MutatingEndpointReference{}),
	}
}

// Prepare is called before the action is started.
// It can be used to validate the parameters and prepare the action.
// It must not cause any harmful effects.
// The passed in state is included in the subsequent calls to start/status/stop.
// So the state should contain all information needed to execute the action and even more important: to be able to stop it.
func (l *stressCPUAction) Prepare(_ context.Context, state *StressCPUActionState, request action_kit_api.PrepareActionRequestBody) (*action_kit_api.PrepareResult, error) {
	duration := toUInt64(request.Config["duration"])
	cpuLoad := toUInt(request.Config["cpuLoad"])
	workers := toUInt(request.Config["workers"])
	if duration == 0 {
		return nil, errors.New("duration must be greater than 0")
	}
	if cpuLoad == 0 {
		return nil, errors.New("cpuLoad must be greater than 0")
	}
	state.stressNGArgs = []string{
		"--cpu", strconv.Itoa(int(workers)),
		"--cpu-load", strconv.Itoa(int(cpuLoad)),
		"--timeout", strconv.Itoa(int(duration)),
	}

	return nil, nil
}

// Start is called to start the action
// You can mutate the state here.
// You can use the result to return messages/errors/metrics or artifacts
func (l *stressCPUAction) Start(_ context.Context, state *StressCPUActionState) (*action_kit_api.StartResult, error) {
	log.Info().Str("message", state.FormattedMessage).Msg("Logging in log action **start**")

	return &action_kit_api.StartResult{
		//These messages will show up in agent log
		Messages: extutil.Ptr([]action_kit_api.Message{
			{
				Level:   extutil.Ptr(action_kit_api.Info),
				Message: fmt.Sprintf("Started logging '%s'", state.FormattedMessage),
			},
		})}, nil
}

// Status is optional.
// If you implement that it will be called periodically to check the status of the action.
// You can use the result to signal that the action is done and to return messages/errors/metrics or artifacts
func (l *stressCPUAction) Status(_ context.Context, state *StressCPUActionState) (*action_kit_api.StatusResult, error) {
	log.Info().Str("message", state.FormattedMessage).Msg("Logging in log action **status**")

	return &action_kit_api.StatusResult{
		//indicate that the action is still running
		Completed: false,
		//These messages will show up in agent log
		Messages: extutil.Ptr([]action_kit_api.Message{
			{
				Level:   extutil.Ptr(action_kit_api.Info),
				Message: fmt.Sprintf("Status for logging '%s'", state.FormattedMessage),
			},
		})}, nil
}

// Stop is called to stop the action
// It will be called even if the start method did not complete successfully.
// It should be implemented in a immutable way, as the agent might to retries if the stop method timeouts.
// You can use the result to return messages/errors/metrics or artifacts
func (l *stressCPUAction) Stop(_ context.Context, state *StressCPUActionState) (*action_kit_api.StopResult, error) {
	log.Info().Str("message", state.FormattedMessage).Msg("Logging in log action **status**")

	return &action_kit_api.StopResult{
		//These messages will show up in agent log
		Messages: extutil.Ptr([]action_kit_api.Message{
			{
				Level:   extutil.Ptr(action_kit_api.Info),
				Message: fmt.Sprintf("Stopped logging '%s'", state.FormattedMessage),
			},
		})}, nil
}
