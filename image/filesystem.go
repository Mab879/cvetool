package image

import (
	"context"
	"fmt"
	"strings"

	"github.com/quay/claircore"
)

type fileSystemImage struct {
	imageDigest string
	layerPaths  []string
	rootDir     string
}

func NewFileSystemImage(ctx context.Context, rootDir string) (*fileSystemImage, error) {
	fsi := &fileSystemImage{}
	fsi.rootDir = rootDir
	return fsi, nil
}

func (i *fileSystemImage) getLayers(ctx context.Context) ([]*claircore.Layer, error) {
	layers := []*claircore.Layer{}

	desc := &claircore.LayerDescription{
		Digest:    fmt.Sprintf("sha256:%s", strings.Repeat("a", 64)),
		URI:       i.rootDir,
		MediaType: "application/vnd.claircore.filesystem",
	}

	l := &claircore.Layer{}
	err := l.Init(ctx, desc, nil)

	if err != nil {
		return nil, err
	}

	l.Close()

	layers = append(layers, l)

	return layers, nil
}

func (i *fileSystemImage) GetManifest(ctx context.Context) (*claircore.Manifest, error) {
	digest, err := claircore.ParseDigest(fmt.Sprintf("sha256:%s", strings.Repeat("b", 64)))
	if err != nil {
		return nil, err
	}

	layers, err := i.getLayers(ctx)
	if err != nil {
		return nil, err
	}

	return &claircore.Manifest{
		Hash:   digest,
		Layers: layers,
	}, nil
}
