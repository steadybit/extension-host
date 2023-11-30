package exthost

import (
	"bytes"
	"context"
	"github.com/rs/zerolog/log"
	"github.com/steadybit/action-kit/go/action_kit_api/v2"
	"github.com/steadybit/action-kit/go/action_kit_sdk"
	"github.com/steadybit/extension-kit/extutil"
	"os"
	"os/exec"
	"strconv"
	"strings"
	"time"
)

type Opts struct {
	CpuWorkers *int
	CpuLoad    int
	HddWorkers *int
	HddBytes   string
	IoWorkers  *int
	TempPath   string
	Timeout    time.Duration
	VmWorkers  *int
	VmHang     time.Duration
	VmBytes    string
}

func (o *Opts) Args() []string {
	args := []string{"--timeout", strconv.Itoa(int(o.Timeout.Seconds()))}
	if o.CpuWorkers != nil {
		args = append(args, "--cpu", strconv.Itoa(*o.CpuWorkers), "--cpu-load", strconv.Itoa(o.CpuLoad))
	}
	if o.HddWorkers != nil {
		args = append(args, "--hdd", strconv.Itoa(*o.HddWorkers))
	}
	if o.HddBytes != "" {
		args = append(args, "--hdd-bytes", o.HddBytes)
	}
	if o.IoWorkers != nil {
		args = append(args, "--io", strconv.Itoa(*o.IoWorkers))
	}
	if o.TempPath != "" {
		args = append(args, "--temp-path", o.TempPath)
	}
	if o.VmWorkers != nil {
		args = append(args, "--vm", strconv.Itoa(*o.VmWorkers), "--vm-bytes", o.VmBytes, "--vm-hang", "0")
	}
	if log.Trace().Enabled() {
		args = append(args, "-v")
	}
	return args
}

type stressOptsProvider func(request action_kit_api.PrepareActionRequestBody) (Opts, error)

type stressAction struct {
	description  action_kit_api.ActionDescription
	optsProvider stressOptsProvider
}

// Make sure action implements all required interfaces
var (
	_ action_kit_sdk.Action[StressActionState]         = (*stressAction)(nil)
	_ action_kit_sdk.ActionWithStop[StressActionState] = (*stressAction)(nil) // Optional, needed when the action needs a stop method
)

func (a *stressAction) NewEmptyState() StressActionState {
	return StressActionState{}
}

// Describe returns the action description for the platform with all required information.
func (a *stressAction) Describe() action_kit_api.ActionDescription {
	return a.description
}

// Prepare is called before the action is started.
// It can be used to validate the parameters and prepare the action.
// It must not cause any harmful effects.
// The passed in state is included in the subsequent calls to start/status/stop.
// So the state should contain all information needed to execute the action and even more important: to be able to stop it.
func (a *stressAction) Prepare(_ context.Context, state *StressActionState, request action_kit_api.PrepareActionRequestBody) (*action_kit_api.PrepareResult, error) {
	if _, err := CheckTargetHostname(request.Target.Attributes); err != nil {
		return nil, err
	}

	if opts, err := a.optsProvider(request); err == nil {
		state.StressNGArgs = opts.Args()
	} else {
		return nil, err
	}

	if !isStressNgInstalled() {
		return &action_kit_api.PrepareResult{
			Error: extutil.Ptr(action_kit_api.ActionKitError{
				Title:  "Stress-ng is not installed!",
				Status: extutil.Ptr(action_kit_api.Errored),
			}),
		}, nil
	}

	return nil, nil
}

// Start is called to start the action
// You can mutate the state here.
// You can use the result to return messages/errors/metrics or artifacts
func (a *stressAction) Start(_ context.Context, state *StressActionState) (*action_kit_api.StartResult, error) {
	pid, err := StartStressNG(state.StressNGArgs)
	if err != nil {
		log.Error().Err(err).Msg("Failed to start stress-ng")
		return nil, err
	}
	log.Info().Int("Pid", pid).Msg("Started stress-ng")
	state.Pid = pid
	return nil, nil
}

// Stop is called to stop the action
// It will be called even if the start method did not complete successfully.
// It should be implemented in a immutable way, as the agent might to retries if the stop method timeouts.
// You can use the result to return messages/errors/metrics or artifacts
func (a *stressAction) Stop(_ context.Context, state *StressActionState) (*action_kit_api.StopResult, error) {
	if state.Pid != 0 {
		log.Info().Int("Pid", state.Pid).Msg("Stopping stress-ng")
		err := StopStressNG(state.Pid)
		if err != nil {
			log.Error().Err(err).Int("Pid", state.Pid).Msg("Failed to stop stress-ng")
			return nil, err
		}
		state.Pid = 0
	}
	return nil, nil
}

type StressActionState struct {
	StressNGArgs []string
	Pid          int
}

func isStressNgInstalled() bool {
	cmd := exec.Command("stress-ng", "-V")
	cmd.Dir = os.TempDir()
	var outputBuffer bytes.Buffer
	cmd.Stdout = &outputBuffer
	cmd.Stderr = &outputBuffer
	err := cmd.Start()
	if err != nil {
		log.Error().Err(err).Msg("failed to Start stress-ng")
		return false
	}
	timer := time.AfterFunc(1*time.Second, func() {
		err := cmd.Process.Kill()
		if err != nil && !strings.Contains(err.Error(), "process already finished") {
			log.Error().Err(err).Msg("failed to kill stress-ng")
			return
		}
	})
	err = cmd.Wait()
	if err != nil {
		log.Error().Err(err).Msg("failed to wait for stress-ng")
		return false
	}
	timer.Stop()
	success := cmd.ProcessState.Success()
	if !success {
		log.Error().Err(err).Msgf("stress-ng is not installed: 'stress-ng -V' in %v returned: %v", os.TempDir(), outputBuffer.Bytes())
	}
	return success
}

func StartStressNG(args []string) (int, error) {
	// Start stress-ng with args
	log.Info().Msgf("Starting stress-ng with args: %v", args)
	cmd := exec.Command("stress-ng", args...)
	cmd.Dir = os.TempDir()
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr
	err := cmd.Start()
	if err != nil {
		return 0, err
	}
	return cmd.Process.Pid, nil
}

func StopStressNG(pid int) error {
	proc, err := os.FindProcess(pid)
	if err != nil {
		log.Error().Err(err).Int("pid", pid).Msg("Failed to find stress-ng process")
		return err
	}
	return proc.Kill()
}
