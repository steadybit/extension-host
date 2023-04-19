package exthost

import (
	"bytes"
	"github.com/rs/zerolog/log"
	"os"
	"os/exec"
	"strings"
	"time"
)

func IsStressNgInstalled() bool {
	cmd := exec.Command("stress-ng", "-V")
	cmd.Dir = os.TempDir()
	var outputBuffer bytes.Buffer
	cmd.Stdout = &outputBuffer
	cmd.Stderr = &outputBuffer
	err := cmd.Start()
	if err != nil {
		log.Error().Err(err).Msg("failed to start stress-ng")
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
	// start stress-ng with args
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
