package image

import (
	"context"
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
