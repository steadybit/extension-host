/*
 * Copyright 2023 steadybit GmbH. All rights reserved.
 */

package exthost

import (
	"context"
	"fmt"
	"github.com/rs/zerolog/log"
	"github.com/steadybit/action-kit/go/action_kit_api/v2"
	"github.com/steadybit/action-kit/go/action_kit_sdk"
	"github.com/steadybit/extension-kit/extbuild"
	"github.com/steadybit/extension-kit/extutil"
)

type logAction struct{}

// Make sure action implements all required interfaces
var (
	_ action_kit_sdk.Action[LogActionState]           = (*logAction)(nil)
	_ action_kit_sdk.ActionWithStatus[LogActionState] = (*logAction)(nil) // Optional, needed when the action needs a status method
	_ action_kit_sdk.ActionWithStop[LogActionState]   = (*logAction)(nil)  // Optional, needed when the action needs a stop method
)

type LogActionState struct {
	FormattedMessage string
}

func NewLogAction() action_kit_sdk.Action[LogActionState] {
	return &logAction{}
}

func (l *logAction) NewEmptyState() LogActionState {
	return LogActionState{}
}

// Describe returns the action description for the platform with all required information.
func (l *logAction) Describe() action_kit_api.ActionDescription {
	return action_kit_api.ActionDescription{
		Id:          fmt.Sprintf("%s.log", targetID),
		Label:       "log",
		Description: "collects information about the monitor status and optionally verifies that the monitor has an expected status.",
		Version:     extbuild.GetSemverVersionStringOrUnknown(),
		Icon:        extutil.Ptr(targetIcon),
		// The target type this action is for
		TargetType: extutil.Ptr(targetID),

		// You can provide a list of target templates to help the user select targets.
		// A template can be used to pre-fill a selection
		TargetSelectionTemplates: extutil.Ptr([]action_kit_api.TargetSelectionTemplate{
			{
				Label: "by robot name",
				Query: "steadybit.label=\"\"",
			},
		}),
		// Category for the targets to appear in
		Category: extutil.Ptr("other"),

		// To clarify the purpose of the action, you can set a kind.
		//   Attack: Will cause harm to targets
		//   Check: Will perform checks on the targets
		//   LoadTest: Will perform load tests on the targets
		//   Other
		Kind: action_kit_api.Other,

		// How the action is controlled over time.
		//   External: The agent takes care and calls stop then the time has passed. Requires a duration parameter. Use this when the duration is known in advance.
		//   Internal: The action has to implement the status endpoint to signal when the action is done. Use this when the duration is not known in advance.
		//   Instantaneous: The action is done immediately. Use this for actions that happen immediately, e.g. a reboot.
		TimeControl: action_kit_api.Internal,

		// The parameters for the action
		Parameters: []action_kit_api.ActionParameter{
			{
				Name:         "message",
				Label:        "Message",
				Description:  extutil.Ptr("What should we log to the console? Use %s to insert the robot name."),
				Type:         action_kit_api.String,
				DefaultValue: extutil.Ptr("Hello from %s"),
				Required:     extutil.Ptr(true),
				Order:        extutil.Ptr(0),
			},
		},
		Status: extutil.Ptr(action_kit_api.MutatingEndpointReferenceWithCallInterval{
			CallInterval: extutil.Ptr("1s"),
		}),
		Stop: extutil.Ptr(action_kit_api.MutatingEndpointReference{}),
	}
}

// Prepare is called before the action is started.
// It can be used to validate the parameters and prepare the action.
// It must not cause any harmful effects.
// The passed in state is included in the subsequent calls to start/status/stop.
// So the state should contain all information needed to execute the action and even more important: to be able to stop it.
func (l *logAction) Prepare(_ context.Context, state *LogActionState, request action_kit_api.PrepareActionRequestBody) (*action_kit_api.PrepareResult, error) {
	log.Info().Str("message", state.FormattedMessage).Msg("Logging in log action **prepare**")
	state.FormattedMessage = fmt.Sprintf(request.Config["message"].(string), request.Target.Name)

	return &action_kit_api.PrepareResult{
		//These messages will show up in agent log
		Messages: extutil.Ptr([]action_kit_api.Message{
			{
				Level:   extutil.Ptr(action_kit_api.Info),
				Message: fmt.Sprintf("Prepared logging '%s'", state.FormattedMessage),
			},
		})}, nil
}

// Start is called to start the action
// You can mutate the state here.
// You can use the result to return messages/errors/metrics or artifacts
func (l *logAction) Start(_ context.Context, state *LogActionState) (*action_kit_api.StartResult, error) {
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
func (l *logAction) Status(_ context.Context, state *LogActionState) (*action_kit_api.StatusResult, error) {
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
func (l *logAction) Stop(_ context.Context, state *LogActionState) (*action_kit_api.StopResult, error) {
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
