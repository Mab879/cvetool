package image

import (
	"context"
	"io/fs"
	"os"
	"path/filepath"
	"testing"
)

func TestManifestFromFilesystem_layerNotPreClosed(t *testing.T) {
	tmp := t.TempDir()
	if err := os.MkdirAll(filepath.Join(tmp, "etc"), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(tmp, "etc", "os-release"), []byte("ID=test\n"), 0o644); err != nil {
		t.Fatal(err)
	}

	mf, err := ManifestFromFilesystem(context.Background(), tmp)
	if err != nil {
		t.Fatalf("ManifestFromFilesystem: %v", err)
	}
	if len(mf.Layers) == 0 {
		t.Fatal("expected at least one layer")
	}

	l := mf.Layers[0]

	defer func() {
		if r := recover(); r != nil {
			t.Fatalf("Close panicked (layer was already closed): %v", r)
		}
	}()
	if err := l.Close(); err != nil {
		t.Fatalf("Close returned error: %v", err)
	}
}

func TestManifestFromFilesystem_relativePathResolvesCorrectly(t *testing.T) {
	tmp := t.TempDir()
	markerDir := filepath.Join(tmp, "var", "lib", "rpm")
	if err := os.MkdirAll(markerDir, 0o755); err != nil {
		t.Fatal(err)
	}
	marker := filepath.Join(markerDir, "rpmdb.sqlite")
	if err := os.WriteFile(marker, []byte("fake"), 0o644); err != nil {
		t.Fatal(err)
	}

	// Use a relative path to trigger the bug
	origDir, err := os.Getwd()
	if err != nil {
		t.Fatal(err)
	}
	parent := filepath.Dir(tmp)
	if err := os.Chdir(parent); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { os.Chdir(origDir) })

	relPath := filepath.Base(tmp)
	mf, err := ManifestFromFilesystem(context.Background(), relPath)
	if err != nil {
		t.Fatalf("ManifestFromFilesystem: %v", err)
	}

	l := mf.Layers[0]
	defer l.Close()

	sys, err := l.FS()
	if err != nil {
		t.Fatalf("FS: %v", err)
	}

	found := false
	fs.WalkDir(sys, ".", func(p string, d fs.DirEntry, err error) error {
		if err != nil {
			return nil
		}
		if filepath.Base(p) == "rpmdb.sqlite" {
			found = true
		}
		return nil
	})
	if !found {
		t.Fatal("layer FS did not find var/lib/rpm/rpmdb.sqlite — relative path was not resolved correctly")
	}
}
