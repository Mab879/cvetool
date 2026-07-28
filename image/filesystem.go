package image

import (
	"context"
	"fmt"
	"strings"

	"github.com/quay/claircore"
)

func ManifestFromFilesystem(ctx context.Context, rootDir string) (*claircore.Manifest, error) {
	digest, err := claircore.ParseDigest(fmt.Sprintf("sha256:%s", strings.Repeat("0", 64)))
	if err != nil {
		return nil, err
	}

	desc := &claircore.LayerDescription{
		Digest:    fmt.Sprintf("sha256:%s", strings.Repeat("1", 64)),
		URI:       "file://" + rootDir,
		MediaType: "application/vnd.claircore.filesystem",
	}

	l := &claircore.Layer{}
	err = l.Init(ctx, desc, nil)
	if err != nil {
		return nil, err
	}
	return &claircore.Manifest{
		Hash:   digest,
		Layers: []*claircore.Layer{l},
	}, nil
}
