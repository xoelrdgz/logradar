package input

import (
	"os"
	"path/filepath"
	"testing"
)

func TestCheckpointOffsetForFileAcceptsCurrentFile(t *testing.T) {
	dir := t.TempDir()
	logPath := filepath.Join(dir, "access.log")
	if err := os.WriteFile(logPath, []byte("one\ntwo\n"), 0600); err != nil {
		t.Fatalf("WriteFile() error = %v", err)
	}

	state, err := checkpointForFile(logPath, 4)
	if err != nil {
		t.Fatalf("checkpointForFile() error = %v", err)
	}

	offset, ok := checkpointOffsetForFile(logPath, state)
	if !ok {
		t.Fatal("checkpointOffsetForFile() ok = false, want true")
	}
	if offset != 4 {
		t.Fatalf("offset = %d, want 4", offset)
	}
}

func TestCheckpointOffsetForFileRejectsTruncatedFile(t *testing.T) {
	dir := t.TempDir()
	logPath := filepath.Join(dir, "access.log")
	if err := os.WriteFile(logPath, []byte("one\ntwo\n"), 0600); err != nil {
		t.Fatalf("WriteFile() error = %v", err)
	}

	state, err := checkpointForFile(logPath, 8)
	if err != nil {
		t.Fatalf("checkpointForFile() error = %v", err)
	}
	if err := os.WriteFile(logPath, []byte("one\n"), 0600); err != nil {
		t.Fatalf("truncate WriteFile() error = %v", err)
	}

	if _, ok := checkpointOffsetForFile(logPath, state); ok {
		t.Fatal("checkpointOffsetForFile() ok = true, want false for truncated file")
	}
}

func TestCheckpointOffsetForFileRejectsCopytruncateRotation(t *testing.T) {
	dir := t.TempDir()
	logPath := filepath.Join(dir, "access.log")
	if err := os.WriteFile(logPath, []byte("one\ntwo\nthree\n"), 0600); err != nil {
		t.Fatalf("WriteFile() error = %v", err)
	}

	state, err := checkpointForFile(logPath, 8)
	if err != nil {
		t.Fatalf("checkpointForFile() error = %v", err)
	}
	if err := os.WriteFile(logPath, []byte("new\n"), 0600); err != nil {
		t.Fatalf("copytruncate WriteFile() error = %v", err)
	}

	if _, ok := checkpointOffsetForFile(logPath, state); ok {
		t.Fatal("checkpointOffsetForFile() ok = true, want false after copytruncate")
	}
}

func TestCheckpointOffsetForFileRejectsDifferentFileIdentity(t *testing.T) {
	dir := t.TempDir()
	logPath := filepath.Join(dir, "access.log")
	replacementPath := filepath.Join(dir, "access.log.replacement")
	if err := os.WriteFile(logPath, []byte("one\ntwo\n"), 0600); err != nil {
		t.Fatalf("WriteFile() error = %v", err)
	}

	state, err := checkpointForFile(logPath, 4)
	if err != nil {
		t.Fatalf("checkpointForFile() error = %v", err)
	}
	if err := os.WriteFile(replacementPath, []byte("one\ntwo\nthree\n"), 0600); err != nil {
		t.Fatalf("replacement WriteFile() error = %v", err)
	}
	replacementState, err := checkpointForFile(replacementPath, 4)
	if err != nil {
		t.Fatalf("replacement checkpointForFile() error = %v", err)
	}

	if state.Device == 0 && state.Inode == 0 {
		t.Skip("file identity is not available on this platform")
	}
	if state.Device == replacementState.Device && state.Inode == replacementState.Inode {
		t.Skip("filesystem reported the same identity for two existing files")
	}
	if err := os.Rename(replacementPath, logPath); err != nil {
		t.Fatalf("replacement Rename() error = %v", err)
	}
	if _, ok := checkpointOffsetForFile(logPath, state); ok {
		t.Fatal("checkpointOffsetForFile() ok = true, want false for replacement file")
	}
}

func TestCheckpointOffsetForFileRejectsRenameRotation(t *testing.T) {
	dir := t.TempDir()
	logPath := filepath.Join(dir, "access.log")
	rotatedPath := filepath.Join(dir, "access.log.1")
	if err := os.WriteFile(logPath, []byte("one\ntwo\n"), 0600); err != nil {
		t.Fatalf("WriteFile() error = %v", err)
	}

	state, err := checkpointForFile(logPath, 4)
	if err != nil {
		t.Fatalf("checkpointForFile() error = %v", err)
	}
	if err := os.Rename(logPath, rotatedPath); err != nil {
		t.Fatalf("Rename() error = %v", err)
	}
	if err := os.WriteFile(logPath, []byte("new\n"), 0600); err != nil {
		t.Fatalf("new log WriteFile() error = %v", err)
	}

	if state.Device == 0 && state.Inode == 0 {
		t.Skip("file identity is not available on this platform")
	}
	if _, ok := checkpointOffsetForFile(logPath, state); ok {
		t.Fatal("checkpointOffsetForFile() ok = true, want false after rename rotation")
	}
}

func TestSaveAndLoadCheckpointRoundTrip(t *testing.T) {
	path := filepath.Join(t.TempDir(), "state", "checkpoint.json")
	state := checkpointState{
		LogPath: "/logs/access.log",
		Offset:  42,
		Size:    100,
		Device:  1,
		Inode:   2,
	}

	if err := saveCheckpoint(path, state); err != nil {
		t.Fatalf("saveCheckpoint() error = %v", err)
	}
	loaded, err := loadCheckpoint(path)
	if err != nil {
		t.Fatalf("loadCheckpoint() error = %v", err)
	}
	if loaded.LogPath != state.LogPath || loaded.Offset != state.Offset || loaded.Device != state.Device || loaded.Inode != state.Inode {
		t.Fatalf("loaded checkpoint = %+v, want %+v", loaded, state)
	}
}
