package input

import (
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"runtime"
	"syscall"
	"time"
)

type checkpointState struct {
	LogPath   string    `json:"log_path"`
	Offset    int64     `json:"offset"`
	Size      int64     `json:"size"`
	Device    uint64    `json:"device,omitempty"`
	Inode     uint64    `json:"inode,omitempty"`
	UpdatedAt time.Time `json:"updated_at"`
}

func loadCheckpoint(path string) (checkpointState, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return checkpointState{}, nil
		}
		return checkpointState{}, err
	}
	if len(data) == 0 {
		return checkpointState{}, nil
	}

	var state checkpointState
	if err := json.Unmarshal(data, &state); err != nil {
		return checkpointState{}, err
	}
	return state, nil
}

func saveCheckpoint(path string, state checkpointState) error {
	if path == "" {
		return nil
	}
	if err := os.MkdirAll(filepath.Dir(path), 0750); err != nil {
		return err
	}

	tmp, err := os.CreateTemp(filepath.Dir(path), ".checkpoint-*")
	if err != nil {
		return err
	}
	tmpName := tmp.Name()
	defer os.Remove(tmpName)

	encoder := json.NewEncoder(tmp)
	encoder.SetIndent("", "  ")
	if err := encoder.Encode(state); err != nil {
		_ = tmp.Close()
		return err
	}
	if err := tmp.Sync(); err != nil {
		_ = tmp.Close()
		return err
	}
	if err := tmp.Close(); err != nil {
		return err
	}
	return os.Rename(tmpName, path)
}

func checkpointForFile(logPath string, offset int64) (checkpointState, error) {
	info, err := os.Stat(logPath)
	if err != nil {
		return checkpointState{}, err
	}
	device, inode := fileIdentity(info)
	return checkpointState{
		LogPath:   logPath,
		Offset:    offset,
		Size:      info.Size(),
		Device:    device,
		Inode:     inode,
		UpdatedAt: time.Now().UTC(),
	}, nil
}

func checkpointOffsetForFile(logPath string, state checkpointState) (int64, bool) {
	if state.Offset <= 0 || state.LogPath != logPath {
		return 0, false
	}

	info, err := os.Stat(logPath)
	if err != nil {
		return 0, false
	}
	if state.Offset > info.Size() {
		return 0, false
	}

	device, inode := fileIdentity(info)
	if state.Device != 0 || state.Inode != 0 {
		if state.Device != device || state.Inode != inode {
			return 0, false
		}
	}

	return state.Offset, true
}

func fileIdentity(info os.FileInfo) (uint64, uint64) {
	if runtime.GOOS == "windows" {
		return 0, 0
	}
	stat, ok := info.Sys().(*syscall.Stat_t)
	if !ok {
		return 0, 0
	}
	return uint64(stat.Dev), uint64(stat.Ino)
}
