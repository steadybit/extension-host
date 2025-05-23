// SPDX-License-Identifier: MIT
// SPDX-FileCopyrightText: 2025 Steadybit GmbH

//go:build linux

package shutdown

import (
	"github.com/rs/zerolog/log"
	"syscall"
	"time"
)

type syscallShutdown struct {
	reboot func(cmd int) (err error)
}

func newSyscallShutdown() Shutdown {
	return &syscallShutdown{reboot: syscall.Reboot}
}

func (s *syscallShutdown) IsAvailable() bool {
	return true
}

func (s *syscallShutdown) Reboot() error {
	return s.runReboot(syscall.LINUX_REBOOT_CMD_RESTART, "LINUX_REBOOT_CMD_RESTART")
}

func (s *syscallShutdown) Shutdown() error {
	return s.runReboot(syscall.LINUX_REBOOT_CMD_POWER_OFF, "LINUX_REBOOT_CMD_POWER_OFF")
}

func (s *syscallShutdown) Name() string {
	return "syscall_linux"
}

func (s *syscallShutdown) runReboot(cmd int, name string) error {
	go func() {
		time.Sleep(3 * time.Second)
		if err := s.reboot(cmd); err != nil {
			log.Err(err).Msgf("failed %s", name)
		}
	}()
	return nil
}
