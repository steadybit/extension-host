// SPDX-License-Identifier: MIT
// SPDX-FileCopyrightText: 2025 Roblox Corporation
// Author: Tom Handal <thandal@roblox.com>

package cpufreq

import (
	"fmt"
	"os"
	"path/filepath"
	"strconv"
	"strings"
)

const (
	cpuGlob        = "cpu[0-9]*"
	minFreqFile    = "cpuinfo_min_freq"
	maxFreqFile    = "cpuinfo_max_freq"
	curFreqFile    = "scaling_cur_freq"
	scalingMinFile = "scaling_min_freq"
	scalingMaxFile = "scaling_max_freq"
	khzToMhz       = 1000 // Convert kHz to MHz
)

var cpuBasePath = "/sys/devices/system/cpu"

// GetCPUFrequencyInfo returns the minimum and maximum CPU frequencies in MHz
func GetCPUFrequencyInfo() (min, max uint64, err error) {
	cpus, err := listCpuDirs()
	if err != nil {
		return 0, 0, err
	}

	cpuPath := filepath.Join(cpus[0], "cpufreq")

	minFreq, err := readFrequencyFile(filepath.Join(cpuPath, minFreqFile))
	if err != nil {
		return 0, 0, fmt.Errorf("failed to read min frequency: %w", err)
	}

	maxFreq, err := readFrequencyFile(filepath.Join(cpuPath, maxFreqFile))
	if err != nil {
		return 0, 0, fmt.Errorf("failed to read max frequency: %w", err)
	}

	// Convert kHz to MHz
	return minFreq / khzToMhz, maxFreq / khzToMhz, nil
}

// GetCurrentFrequency returns the current CPU frequency in MHz
func GetCurrentFrequency() (uint64, error) {
	cpus, err := listCpuDirs()
	if err != nil {
		return 0, err
	}

	freqKhz, err := readFrequencyFile(filepath.Join(cpus[0], "cpufreq", curFreqFile))
	if err != nil {
		return 0, err
	}

	// Convert kHz to MHz
	return freqKhz / khzToMhz, nil
}

// SetCPUFrequencyLimits sets the minimum and maximum CPU frequency for all cores
// Frequencies are specified in MHz but written to sysfs in kHz
func SetCPUFrequencyLimits(min, max uint64) error {
	if min > max {
		return fmt.Errorf("minimum frequency %d MHz cannot be greater than maximum frequency %d MHz", min, max)
	}

	// Get current min/max to validate requested values
	curMin, curMax, err := GetCPUFrequencyInfo()
	if err != nil {
		return fmt.Errorf("failed to get current CPU frequency limits: %w", err)
	}

	if min < curMin {
		return fmt.Errorf("requested minimum frequency %d MHz is below hardware minimum %d MHz", min, curMin)
	}
	if max > curMax {
		return fmt.Errorf("requested maximum frequency %d MHz is above hardware maximum %d MHz", max, curMax)
	}

	// Convert MHz to kHz for sysfs
	minKhz := min * khzToMhz
	maxKhz := max * khzToMhz

	cpus, err := listCpuDirs()
	if err != nil {
		return err
	}

	for _, cpu := range cpus {
		cpuPath := filepath.Join(cpu, "cpufreq")

		// Set max first when lowering, min first when raising to avoid invalid states
		if maxKhz < curMax*khzToMhz {
			if err := writeFrequencyFile(filepath.Join(cpuPath, scalingMaxFile), maxKhz); err != nil {
				return fmt.Errorf("failed to set max frequency for %s: %w", cpu, err)
			}
			if err := writeFrequencyFile(filepath.Join(cpuPath, scalingMinFile), minKhz); err != nil {
				return fmt.Errorf("failed to set min frequency for %s: %w", cpu, err)
			}
		} else {
			if err := writeFrequencyFile(filepath.Join(cpuPath, scalingMinFile), minKhz); err != nil {
				return fmt.Errorf("failed to set min frequency for %s: %w", cpu, err)
			}
			if err := writeFrequencyFile(filepath.Join(cpuPath, scalingMaxFile), maxKhz); err != nil {
				return fmt.Errorf("failed to set max frequency for %s: %w", cpu, err)
			}
		}
	}

	return nil
}

func listCpuDirs() ([]string, error) {
	cpus, err := filepath.Glob(filepath.Join(cpuBasePath, cpuGlob))
	if err != nil {
		return nil, fmt.Errorf("failed to list CPU directories: %w", err)
	}

	if len(cpus) == 0 {
		return nil, fmt.Errorf("no CPUs found")
	}

	return cpus, nil
}

// readFrequencyFile reads a frequency value in kHz from a sysfs file
func readFrequencyFile(path string) (uint64, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return 0, err
	}
	return strconv.ParseUint(strings.TrimSpace(string(data)), 10, 64)
}

// writeFrequencyFile writes a frequency value in kHz to a sysfs file
func writeFrequencyFile(path string, value uint64) error {
	return os.WriteFile(path, fmt.Appendf(nil, "%d", value), 0644)
}
