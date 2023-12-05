package timetravel

import (
	"errors"
	"github.com/rs/zerolog/log"
	"syscall"
	"time"
)

func AdjustTime(offset time.Duration, negate bool) error {
	tp := syscall.Timeval{}
	err := syscall.Gettimeofday(&tp)
	initialTime := tp.Sec
	log.Info().Msgf("Current time: %d", tp.Sec)
	if err != nil {
		log.Err(err).Msg("Could not change time offset - Gettimeofday")
		return err
	}
	seconds := int64(offset.Seconds())
	if negate {
		seconds = -seconds
	}
	log.Info().Msgf("Adjusting time by %d seconds", seconds)
	tp.Sec += seconds
	err = syscall.Settimeofday(&tp)
	if err != nil {
		log.Err(err).Msg("Could not change time offset - Settimeofday")
		return err
	}
	newTime := tp.Sec
	log.Info().Msgf("New time: %d", tp.Sec)
	diff := newTime - initialTime
	if diff < 0 {
		diff = -diff
	}
	log.Info().Msgf("Time difference: %d", diff)
	normalizedOffset := offset.Seconds()
	if offset < 0 {
		normalizedOffset = -normalizedOffset
	}
	minDiff := normalizedOffset * 0.8
	maxDiff := normalizedOffset * 1.2
	if float64(diff) >= minDiff && float64(diff) <= maxDiff {
		return nil
	} else {
		return errors.New("time offset not applied")
	}
}
