// SPDX-License-Identifier: MIT
// SPDX-FileCopyrightText: 2023 Steadybit GmbH

package network

import (
	"bytes"
	"context"
	"fmt"
	"github.com/rs/zerolog/log"
	networkutils "github.com/steadybit/action-kit/go/action_kit_commons/network"
	"os"
	"os/exec"
	"syscall"
)

func Apply(ctx context.Context, hostname string, opts networkutils.Opts) error {
	log.Info().
		Str("hostname", hostname).
		Msg("applying network config")

	return generateAndRunCommands(ctx, opts, networkutils.ModeAdd)
}

func generateAndRunCommands(ctx context.Context, opts networkutils.Opts, mode networkutils.Mode) error {
	ipCommandsV4, err := opts.IpCommands(networkutils.FamilyV4, mode)
	if err != nil {
		log.Error().Msgf("failed to get ipCommandsV4: %v", err)
		return err
	}

	ipCommandsV6, err := opts.IpCommands(networkutils.FamilyV6, mode)
	if err != nil {
		log.Error().Msgf("failed to get ipCommandsV6: %v", err)
		return err
	}

	tcCommands, err := opts.TcCommands(mode)
	if err != nil {
		log.Error().Msgf("failed to get tcCommands: %v", err)
		return err
	}

	if ipCommandsV4 != nil {
		err = executeIpCommands(ctx, networkutils.FamilyV4, ipCommandsV4)
		if err != nil {
			log.Error().Msgf("failed to executeIpCommands: %v", err)
			return err
		}
	}

	if ipCommandsV6 != nil {
		err = executeIpCommands(ctx, networkutils.FamilyV6, ipCommandsV6)
		if err != nil {
			log.Error().Msgf("failed to executeIpCommands: %v", err)
			return err
		}
	}

	if tcCommands != nil {
		err = executeTcCommands(ctx, tcCommands)
		if err != nil {
			return networkutils.FilterBatchErrors(err, mode, tcCommands)
		}
	}

	return nil
}

func Revert(ctx context.Context, hostname string, opts networkutils.Opts) error {
	log.Info().
		Str("hostname", hostname).
		Msg("reverting network config")

	return generateAndRunCommands(ctx, opts, networkutils.ModeDelete)

}

func executeIpCommands(ctx context.Context, family networkutils.Family, cmds []string) error {
	if len(cmds) == 0 {
		return nil
	}

	log.Debug().Strs("cmds", cmds).Str("family", string(family)).Msg("running ip commands")
	cmd := exec.CommandContext(ctx, "ip", "-family", string(family), "-force", "-batch", "-")
	cmd.Stdin = networkutils.ToReader(cmds)
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr
	cmd.SysProcAttr = &syscall.SysProcAttr{
		Credential: &syscall.Credential{
			Uid: 0,
			Gid: 0,
		},
	}
	err := cmd.Run()
	if err != nil {
		return err
	}

	return nil
}

func executeTcCommands(ctx context.Context, cmds []string) error {
	if len(cmds) == 0 {
		return nil
	}

	log.Debug().Strs("cmds", cmds).Msg("running tc commands")
	var outb bytes.Buffer
	cmd := exec.CommandContext(ctx, "tc", "-force", "-batch", "-")
	cmd.Stdin = networkutils.ToReader(cmds)
	cmd.Stdout = &outb
	cmd.Stderr = &outb
	cmd.SysProcAttr = &syscall.SysProcAttr{
		Credential: &syscall.Credential{
			Uid: 0,
			Gid: 0,
		},
	}
	err := cmd.Run()
	if err != nil {
		if parsed := networkutils.ParseBatchError(cmds, bytes.NewReader(outb.Bytes())); parsed != nil {
			return parsed
		}
		return fmt.Errorf("tc failed: %w, output: %s", err, outb.String())
	}

	return nil
}
