package exthost

import (
	"github.com/rs/zerolog/log"
	"os"
	"os/exec"
	"time"
)

func isStressNgInstalled() bool {
	cmd := exec.Command("stress-ng", "-V")
	cmd.Dir = os.TempDir()
	if err := cmd.Start(); err != nil {
		log.Error().Err(err).Msg("failed to start stress-ng")
	}
	timer := time.AfterFunc(1*time.Second, func() {
		err := cmd.Process.Kill()
		if err != nil {
			log.Error().Err(err).Msg("failed to kill stress-ng")
			return
		}
	})
	err := cmd.Wait()
	if err != nil {
		log.Error().Err(err).Msg("failed to wait for stress-ng")
	}
	timer.Stop()
	success := cmd.ProcessState.Success()
	if !success {
		log.Error().Err(err).Msgf("stress-ng is not installed: 'stress-ng -V' in %v returned: %v", os.TempDir(), cmd.Er)
	}
	return success
}
