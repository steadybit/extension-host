// SPDX-License-Identifier: MIT
// SPDX-FileCopyrightText: 2025 Steadybit GmbH

package stopprocess

import (
	"errors"
	"fmt"
	"github.com/mitchellh/go-ps"
	"github.com/rs/zerolog/log"
	"github.com/steadybit/extension-host/exthost/common"
	"github.com/steadybit/extension-kit/extutil"
	"strings"
	"syscall"
)

func StopProcesses(pid []int, force bool) error {
	if len(pid) == 0 {
		return nil
	}

	var errs error
	for _, p := range pid {
		if process, err := ps.FindProcess(p); err == nil {
			log.Info().Int("pid", p).Str("name", process.Executable()).Msg("Stopping process")
		} else {
			continue
		}

		if err := stopProcessUnix(p, force); err != nil {
			errs = errors.Join(errs, err)
		}
	}

	if errs != nil {
		return fmt.Errorf("fail to stop processes : %w", errs)
	}
	return nil
}

func stopProcessUnix(pid int, force bool) error {
	if force {
		err := syscall.Kill(pid, syscall.SIGKILL)
		if err != nil {
			log.Debug().Err(err).Int("pid", pid).Msg("Failed to send SIGKILL via syscall")
			err = common.RunAsRoot("kill", "-9", fmt.Sprintf("%d", pid))
		}
		if err != nil {
			return fmt.Errorf("failed to send SIGKILL process via exec: %w", err)
		}
		return err
	}

	err := syscall.Kill(pid, syscall.SIGTERM)
	if err != nil {
		log.Error().Err(err).Int("pid", pid).Msg("failed to send SIGTERM via syscall")
		err = common.RunAsRoot("kill", fmt.Sprintf("%d", pid))
	}
	if err != nil {
		return fmt.Errorf("failed to send SIGTERM via exec: %w", err)
	}
	return err
}

func FindProcessIds(processOrPid string) []int {
	pid := extutil.ToInt(processOrPid)
	if pid > 0 {
		return []int{pid}
	}

	var pids []int
	processes, err := ps.Processes()
	if err != nil {
		log.Error().Err(err).Msg("Failed to list processes")
		return nil
	}
	for _, process := range processes {
		if strings.Contains(strings.TrimSpace(process.Executable()), processOrPid) {
			pids = append(pids, process.Pid())
		}
	}
	return pids
}
