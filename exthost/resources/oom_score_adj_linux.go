//go:build linux

package resources

import (
	"github.com/rs/zerolog/log"
	"github.com/steadybit/extension-host/exthost/common"
	"os"
	"path/filepath"
	"strconv"
)

func AdjustOOMScoreAdj() {
	log.Debug().Msg("Adjusting OOM score")
	path := filepath.Join("/proc", strconv.Itoa(os.Getpid()), "oom_score_adj")
	if err := common.RunAsRoot("sh", "-c", "echo -997 > "+path); err != nil {
		log.Warn().Err(err).Msg("Failed to adjust OOM score")
	}

	if oomScore, err := os.ReadFile(path); err == nil {
		log.Debug().Msgf("%s: %s", path, oomScore)
	}
}
