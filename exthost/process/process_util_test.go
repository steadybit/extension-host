package stopprocess

import (
	"github.com/stretchr/testify/assert"
	"os/exec"
	"testing"
)

func TestStopProcesses(t *testing.T) {
	command := exec.Command("tail", "-f", "/dev/null", "&")
	err := command.Start()
	assert.NoError(t, err)
	ids := FindProcessIds("tail")
	assert.Equal(t, 1, len(ids))
	assert.Equal(t, command.Process.Pid, ids[0])
	err = StopProcesses(ids, true)
	assert.NoError(t, err)
}

func TestStopProcessesSkipsVanishedPid(t *testing.T) {
	nonExistentPid := 4194303
	assert.NotPanics(t, func() {
		err := StopProcesses([]int{nonExistentPid}, true)
		assert.NoError(t, err)
	})
}
