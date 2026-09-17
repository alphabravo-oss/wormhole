package main

import (
	"os"
	"testing"
	"time"

	"github.com/restic/restic/internal/data"
)

func TestMetadataEqualPortable(t *testing.T) {
	a := &data.Node{
		Name: "file", Type: data.NodeTypeFile, Mode: 0640, UID: 1000, GID: 1000,
		Size: 4, Inode: 10, DeviceID: 20, Links: 1,
		ModTime: time.Unix(10, 0), AccessTime: time.Unix(11, 0), ChangeTime: time.Unix(12, 0),
	}
	b := *a
	b.Inode, b.DeviceID = 99, 88
	b.AccessTime, b.ChangeTime = time.Unix(30, 0), time.Unix(40, 0)
	if !metadataEqual(a, &b, true, false) {
		t.Fatal("portable comparison rejected host-specific metadata")
	}
	if metadataEqual(a, &b, false, false) {
		t.Fatal("exact comparison ignored host-specific metadata")
	}
	b.ModTime = time.Unix(20, 0)
	if metadataEqual(a, &b, true, false) || !metadataEqual(a, &b, true, true) {
		t.Fatal("file modification time was ignored outside fresh-target comparison")
	}
	b.Mode = os.FileMode(0600)
	if metadataEqual(a, &b, true, true) {
		t.Fatal("portable comparison ignored mode change")
	}
	dirA := &data.Node{Name: "dir", Type: data.NodeTypeDir, Mode: os.ModeDir | 0750, ModTime: time.Unix(1, 0), Links: 2}
	dirB := *dirA
	dirB.ModTime, dirB.Links = time.Unix(2, 0), 9
	if !metadataEqual(dirA, &dirB, true, false) {
		t.Fatal("portable comparison treated child-driven directory metadata as drift")
	}
}
