package timetravel

import (
	"github.com/rs/zerolog/log"
	"os/exec"
	"strings"
	"syscall"
)

func executeIpTablesCommand(args ...string) error {
	log.Debug().Msg("Executing iptables command")
	log.Debug().Msg(strings.Join(args, " "))
	cmd := exec.Command("iptables", args...)
	cmd.SysProcAttr = &syscall.SysProcAttr{
		Credential: &syscall.Credential{
			Uid: 0,
			Gid: 0,
		},
	}

	cmd.Env = append(cmd.Env, "XTABLES_LOCKFILE=/tmp/xtables.lock")
	out, err := cmd.CombinedOutput()
	if err != nil {
		log.Error().Err(err).Str("output", string(out)).Msg("Failed to execute iptables command")
		return err
	}

	return nil
}
func adjustNtpTrafficRules(allowNtpTraffic bool) error {
	if allowNtpTraffic {
		err := executeIpTablesCommand("-A", "OUTPUT", "-p", "udp", "--dport", "123", "-j", "ACCEPT")
		if err != nil {
			log.Error().Err(err).Msg("Failed to execute iptables command")
			return err
		}
		err = executeIpTablesCommand("-A", "OUTPUT", "-p", "udp", "--sport", "123", "-j", "ACCEPT")
		if err != nil {
			log.Error().Err(err).Msg("Failed to execute iptables command")
			return err
		}
	} else {
		err := executeIpTablesCommand("-A", "OUTPUT", "-p", "udp", "--dport", "123", "-j", "DROP")
		if err != nil {
			log.Error().Err(err).Msg("Failed to execute iptables command")
			return err
		}
		err = executeIpTablesCommand("-A", "OUTPUT", "-p", "udp", "--sport", "123", "-j", "DROP")
		if err != nil {
			log.Error().Err(err).Msg("Failed to execute iptables command")
			return err
		}
	}
	return nil
}
