// SPDX-License-Identifier: MIT
// SPDX-FileCopyrightText: 2025 Roblox Corporation
// Author: Tom Handal <thandal@roblox.com>

package exthost

import (
	"context"
	"fmt"
	"time"

	"github.com/rs/zerolog/log"
	"github.com/steadybit/action-kit/go/action_kit_api/v2"
	"github.com/steadybit/action-kit/go/action_kit_sdk"
	"github.com/steadybit/extension-host/exthost/cpufreq"
	"github.com/steadybit/extension-kit/extbuild"
	"github.com/steadybit/extension-kit/extutil"
)

type cpuSpeedAction struct{}

type CpuSpeedActionState struct {
	OriginalMinFreq uint64
	OriginalMaxFreq uint64
	NewMinFreq      uint64
	NewMaxFreq      uint64
	FreqsApplied    bool
}

// Make sure action implements all required interfaces
var (
	_ action_kit_sdk.Action[CpuSpeedActionState]           = (*cpuSpeedAction)(nil)
	_ action_kit_sdk.ActionWithStop[CpuSpeedActionState]   = (*cpuSpeedAction)(nil)
	_ action_kit_sdk.ActionWithStatus[CpuSpeedActionState] = (*cpuSpeedAction)(nil)
)

func NewCpuSpeedAction() action_kit_sdk.Action[CpuSpeedActionState] {
	return &cpuSpeedAction{}
}

func (a *cpuSpeedAction) NewEmptyState() CpuSpeedActionState {
	return CpuSpeedActionState{}
}

func (a *cpuSpeedAction) Describe() action_kit_api.ActionDescription {
	return action_kit_api.ActionDescription{
		Id:          fmt.Sprintf("%s.cpu-speed", BaseActionID),
		Label:       "Change CPU Frequency",
		Description: "Changes the CPU frequency limits for all cores for the given duration.",
		Version:     extbuild.GetSemverVersionStringOrUnknown(),
		Icon:        extutil.Ptr(changeCPUSpeed),
		TargetSelection: &action_kit_api.TargetSelection{
			TargetType:         targetID + "(host.cpu.min_freq)",
			SelectionTemplates: &targetSelectionTemplates,
		},
		Technology:  extutil.Ptr("Linux Host"),
		Category:    extutil.Ptr("Resource"),
		Kind:        action_kit_api.Attack,
		TimeControl: action_kit_api.TimeControlExternal,
		Widgets: extutil.Ptr([]action_kit_api.Widget{
			action_kit_api.LineChartWidget{
				Type:  action_kit_api.ComSteadybitWidgetLineChart,
				Title: "CPU Frequency",
				Identity: action_kit_api.LineChartWidgetIdentityConfig{
					MetricName: "response_time",
					From:       "freq_type",
					Mode:       action_kit_api.ComSteadybitWidgetLineChartIdentityModeWidgetPerValue,
				},
				Grouping: extutil.Ptr(action_kit_api.LineChartWidgetGroupingConfig{
					ShowSummary: extutil.Ptr(true),
					Groups: []action_kit_api.LineChartWidgetGroup{
						{
							Title: "Current",
							Color: "info",
							Matcher: action_kit_api.LineChartWidgetGroupMatcherKeyEqualsValue{
								Type:  action_kit_api.ComSteadybitWidgetLineChartGroupMatcherKeyEqualsValue,
								Key:   "freq_type",
								Value: "Current",
							},
						},
						{
							Title: "Minimum",
							Color: "warn",
							Matcher: action_kit_api.LineChartWidgetGroupMatcherKeyEqualsValue{
								Type:  action_kit_api.ComSteadybitWidgetLineChartGroupMatcherKeyEqualsValue,
								Key:   "freq_type",
								Value: "Minimum",
							},
						},
						{
							Title: "Maximum",
							Color: "success",
							Matcher: action_kit_api.LineChartWidgetGroupMatcherKeyEqualsValue{
								Type:  action_kit_api.ComSteadybitWidgetLineChartGroupMatcherKeyEqualsValue,
								Key:   "freq_type",
								Value: "Maximum",
							},
						},
					},
				}),
				Tooltip: extutil.Ptr(action_kit_api.LineChartWidgetTooltipConfig{
					MetricValueTitle: extutil.Ptr("Frequency"),
					MetricValueUnit:  extutil.Ptr("MHz"),
					AdditionalContent: []action_kit_api.LineChartWidgetTooltipContent{
						{
							From:  "freq_type",
							Title: "Type",
						},
					},
				}),
			},
		}),
		Parameters: []action_kit_api.ActionParameter{
			{
				Name:         "minFreq",
				Label:        "Minimum CPU Frequency (MHz)",
				Description:  extutil.Ptr("The minimum CPU frequency to set in MHz. Must be within the CPU's supported range."),
				Type:         action_kit_api.ActionParameterTypeInteger,
				Required:     extutil.Ptr(true),
				Order:        extutil.Ptr(1),
				DefaultValue: extutil.Ptr("1000"),
			},
			{
				Name:         "maxFreq",
				Label:        "Maximum CPU Frequency (MHz)",
				Description:  extutil.Ptr("The maximum CPU frequency to set in MHz. Must be within the CPU's supported range."),
				Type:         action_kit_api.ActionParameterTypeInteger,
				Required:     extutil.Ptr(true),
				Order:        extutil.Ptr(2),
				DefaultValue: extutil.Ptr("2000"),
			},
			{
				Name:         "duration",
				Label:        "Duration",
				Description:  extutil.Ptr("How long should the CPU frequency be limited?"),
				Type:         action_kit_api.ActionParameterTypeDuration,
				DefaultValue: extutil.Ptr("60s"),
				Required:     extutil.Ptr(true),
				Order:        extutil.Ptr(3),
			},
		},
		Stop: extutil.Ptr(action_kit_api.MutatingEndpointReference{}),
	}
}

func (a *cpuSpeedAction) Prepare(_ context.Context, state *CpuSpeedActionState, request action_kit_api.PrepareActionRequestBody) (*action_kit_api.PrepareResult, error) {
	if _, err := CheckTargetHostname(request.Target.Attributes); err != nil {
		return nil, err
	}

	minFreq, maxFreq, err := cpufreq.GetCPUFrequencyInfo()
	if err != nil {
		return &action_kit_api.PrepareResult{
			Error: extutil.Ptr(action_kit_api.ActionKitError{
				Title:  "CPU frequency control is not supported on this host",
				Status: extutil.Ptr(action_kit_api.Errored),
				Detail: extutil.Ptr(err.Error()),
			}),
		}, nil
	}

	state.OriginalMinFreq = minFreq
	state.OriginalMaxFreq = maxFreq

	state.NewMinFreq = extutil.ToUInt64(request.Config["minFreq"])
	state.NewMaxFreq = extutil.ToUInt64(request.Config["maxFreq"])

	if state.NewMinFreq < minFreq {
		return &action_kit_api.PrepareResult{
			Error: extutil.Ptr(action_kit_api.ActionKitError{
				Title:  "Minimum frequency too low",
				Status: extutil.Ptr(action_kit_api.Errored),
				Detail: extutil.Ptr(fmt.Sprintf("Requested minimum frequency %d MHz is below hardware minimum %d MHz", state.NewMinFreq, minFreq)),
			}),
		}, nil
	}

	if state.NewMaxFreq > maxFreq {
		return &action_kit_api.PrepareResult{
			Error: extutil.Ptr(action_kit_api.ActionKitError{
				Title:  "Maximum frequency too high",
				Status: extutil.Ptr(action_kit_api.Errored),
				Detail: extutil.Ptr(fmt.Sprintf("Requested maximum frequency %d MHz is above hardware maximum %d MHz", state.NewMaxFreq, maxFreq)),
			}),
		}, nil
	}

	if state.NewMinFreq > state.NewMaxFreq {
		return &action_kit_api.PrepareResult{
			Error: extutil.Ptr(action_kit_api.ActionKitError{
				Title:  "Invalid frequency range",
				Status: extutil.Ptr(action_kit_api.Errored),
				Detail: extutil.Ptr(fmt.Sprintf("Minimum frequency %d MHz cannot be greater than maximum frequency %d MHz", state.NewMinFreq, state.NewMaxFreq)),
			}),
		}, nil
	}

	return &action_kit_api.PrepareResult{
		Messages: extutil.Ptr([]action_kit_api.Message{
			{
				Level:   extutil.Ptr(action_kit_api.Info),
				Message: fmt.Sprintf("Prepared CPU frequency limits to min=%d MHz, max=%d MHz", state.NewMinFreq, state.NewMaxFreq),
			},
		}),
	}, nil
}

func (a *cpuSpeedAction) Start(_ context.Context, state *CpuSpeedActionState) (*action_kit_api.StartResult, error) {
	log.Info().
		Uint64("min_freq", state.NewMinFreq).
		Uint64("max_freq", state.NewMaxFreq).
		Msg("Setting CPU frequency limits")

	if err := cpufreq.SetCPUFrequencyLimits(state.NewMinFreq, state.NewMaxFreq); err != nil {
		log.Error().Err(err).Msg("Failed to set CPU frequency limits")
		return nil, err
	}

	// Get current frequency for metrics
	currentFreq, err := cpufreq.GetCurrentFrequency()
	if err != nil {
		log.Error().Err(err).Msg("Failed to get current CPU frequency")
		return nil, err
	}

	state.FreqsApplied = true
	now := time.Now()
	return &action_kit_api.StartResult{
		Metrics: extutil.Ptr([]action_kit_api.Metric{
			{
				Name: extutil.Ptr("response_time"),
				Metric: map[string]string{
					"freq_type": "Current",
				},
				Value:     float64(currentFreq),
				Timestamp: now,
			},
			{
				Name: extutil.Ptr("response_time"),
				Metric: map[string]string{
					"freq_type": "Minimum",
				},
				Value:     float64(state.NewMinFreq),
				Timestamp: now,
			},
			{
				Name: extutil.Ptr("response_time"),
				Metric: map[string]string{
					"freq_type": "Maximum",
				},
				Value:     float64(state.NewMaxFreq),
				Timestamp: now,
			},
		}),
		Messages: extutil.Ptr([]action_kit_api.Message{
			{
				Level:   extutil.Ptr(action_kit_api.Info),
				Message: fmt.Sprintf("Set CPU frequency limits to min=%d MHz, max=%d MHz", state.NewMinFreq, state.NewMaxFreq),
			},
		}),
	}, nil
}

func (a *cpuSpeedAction) Stop(_ context.Context, state *CpuSpeedActionState) (*action_kit_api.StopResult, error) {
	if !state.FreqsApplied {
		log.Debug().Msg("No frequency limits applied, skipping revert")
		return nil, nil
	}

	log.Info().
		Uint64("min_freq", state.OriginalMinFreq).
		Uint64("max_freq", state.OriginalMaxFreq).
		Msg("Restoring original CPU frequency limits")

	if err := cpufreq.SetCPUFrequencyLimits(state.OriginalMinFreq, state.OriginalMaxFreq); err != nil {
		log.Error().Err(err).Msg("Failed to restore CPU frequency limits")
		return nil, err
	}

	state.FreqsApplied = false
	return &action_kit_api.StopResult{
		Messages: extutil.Ptr([]action_kit_api.Message{
			{
				Level:   extutil.Ptr(action_kit_api.Info),
				Message: fmt.Sprintf("Restored CPU frequency limits to min=%d MHz, max=%d MHz", state.OriginalMinFreq, state.OriginalMaxFreq),
			},
		}),
	}, nil
}

// Status is called to get the current status of the action
func (a *cpuSpeedAction) Status(_ context.Context, state *CpuSpeedActionState) (*action_kit_api.StatusResult, error) {
	// Get current frequency for metrics
	currentFreq, err := cpufreq.GetCurrentFrequency()
	if err != nil {
		log.Error().Err(err).Msg("Failed to get current CPU frequency")
		return nil, err
	}

	now := time.Now()
	return &action_kit_api.StatusResult{
		Completed: false,
		Metrics: extutil.Ptr([]action_kit_api.Metric{
			{
				Name: extutil.Ptr("response_time"),
				Metric: map[string]string{
					"freq_type": "Current",
				},
				Value:     float64(currentFreq),
				Timestamp: now,
			},
			{
				Name: extutil.Ptr("response_time"),
				Metric: map[string]string{
					"freq_type": "Minimum",
				},
				Value:     float64(state.NewMinFreq),
				Timestamp: now,
			},
			{
				Name: extutil.Ptr("response_time"),
				Metric: map[string]string{
					"freq_type": "Maximum",
				},
				Value:     float64(state.NewMaxFreq),
				Timestamp: now,
			},
		}),
	}, nil
}
