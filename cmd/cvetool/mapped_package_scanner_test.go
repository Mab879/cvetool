package main

import (
	"context"
	"errors"
	"log/slog"
	"net/url"
	"strings"
	"testing"

	"github.com/quay/claircore"
	"github.com/quay/claircore/indexer"
	"github.com/quay/claircore/rhel"
)

var testPackageRepositoryMap = map[string]string{
	"mapped-baseos-package":    "rhel-test-baseos",
	"mapped-appstream-package": "rhel-test-appstream",
}

type testPackageScanner struct {
	packages []*claircore.Package
	err      error
}

func (s *testPackageScanner) Name() string    { return "test-package-scanner" }
func (s *testPackageScanner) Version() string { return "test-version" }
func (s *testPackageScanner) Kind() string    { return indexer.Package }
func (s *testPackageScanner) Scan(context.Context, *claircore.Layer) ([]*claircore.Package, error) {
	return s.packages, s.err
}

func captureWarnings(t *testing.T) *strings.Builder {
	t.Helper()
	var output strings.Builder
	previous := slog.Default()
	slog.SetDefault(slog.New(slog.NewTextHandler(&output, &slog.HandlerOptions{Level: slog.LevelWarn})))
	t.Cleanup(func() { slog.SetDefault(previous) })
	return &output
}

func TestMappedPackageScannerRewritesHints(t *testing.T) {
	warnings := captureWarnings(t)
	mapped := &claircore.Package{
		Name:           "mapped-baseos-package",
		Version:        "1.2.3",
		Arch:           "x86_64",
		RepositoryHint: "repoid=installer-repo&checksum=abc&key_id=signing-key",
	}
	unmapped := &claircore.Package{
		Name:           "unmapped-package",
		RepositoryHint: "repoid=custom-repo&checksum=def&key_id=other-key",
	}
	missing := &claircore.Package{Name: "mapped-appstream-package"}
	unchanged := &claircore.Package{Name: "unmapped-no-repo", RepositoryHint: "checksum=ghi&key_id=key"}

	scanner := NewMappedPackageScanner(&testPackageScanner{packages: []*claircore.Package{mapped, unmapped, missing, unchanged}}, testPackageRepositoryMap)
	got, err := scanner.Scan(context.Background(), &claircore.Layer{})
	if err != nil {
		t.Fatalf("Scan() error = %v", err)
	}
	if len(got) != 4 || got[0] != mapped || got[1] != unmapped || got[2] != missing || got[3] != unchanged {
		t.Fatalf("Scan() changed package order or pointers: %#v", got)
	}

	assertHint(t, mapped.RepositoryHint, map[string]string{"repoid": "rhel-test-baseos", "checksum": "abc", "key_id": "signing-key"})
	if mapped.Version != "1.2.3" || mapped.Arch != "x86_64" {
		t.Errorf("unrelated package fields changed: version=%q arch=%q", mapped.Version, mapped.Arch)
	}
	assertHint(t, unmapped.RepositoryHint, map[string]string{"checksum": "def", "key_id": "other-key"})
	assertHint(t, missing.RepositoryHint, map[string]string{"repoid": "rhel-test-appstream"})
	if unchanged.RepositoryHint != "checksum=ghi&key_id=key" {
		t.Errorf("unmapped hint without repoid changed to %q", unchanged.RepositoryHint)
	}
	if !strings.Contains(warnings.String(), "unmapped-package") || !strings.Contains(warnings.String(), "broad repository association") {
		t.Errorf("warning does not identify unmapped package and fallback: %q", warnings.String())
	}
}

func TestMappedPackageScannerHandlesMalformedAndNilPackages(t *testing.T) {
	warnings := captureWarnings(t)
	malformed := &claircore.Package{Name: "malformed", RepositoryHint: "repoid=%zz&checksum=preserve"}
	valid := &claircore.Package{Name: "valid"}
	scanner := NewMappedPackageScanner(&testPackageScanner{packages: []*claircore.Package{nil, malformed, valid}}, testPackageRepositoryMap)

	got, err := scanner.Scan(context.Background(), &claircore.Layer{})
	if err != nil {
		t.Fatalf("Scan() error = %v", err)
	}
	if len(got) != 2 || got[0] != malformed || got[1] != valid {
		t.Fatalf("unexpected package result: %#v", got)
	}
	if malformed.RepositoryHint != "" {
		t.Errorf("malformed hint = %q, want empty", malformed.RepositoryHint)
	}
	report, err := (&rhel.Coalescer{}).Coalesce(context.Background(), []*indexer.LayerArtifacts{{
		Pkgs:  got,
		Repos: []*claircore.Repository{{ID: "repo-id", URI: "repoid=rhel-test-baseos"}},
	}})
	if err != nil {
		t.Fatalf("Coalesce() error = %v", err)
	}
	if got := report.Environments[malformed.ID][0].RepositoryIDs; len(got) != 1 || got[0] != "repo-id" {
		t.Fatalf("malformed package association = %v, want broad association", got)
	}
	if !strings.Contains(warnings.String(), "malformed") || !strings.Contains(warnings.String(), "nil package") {
		t.Errorf("warnings = %q", warnings.String())
	}
}

func TestMappedPackageScannerPropagatesErrorsWithoutEnrichment(t *testing.T) {
	packages := []*claircore.Package{{Name: "mapped-baseos-package", RepositoryHint: "repoid=old"}}
	wantErr := errors.New("scanner failed")
	scanner := NewMappedPackageScanner(&testPackageScanner{packages: packages, err: wantErr}, testPackageRepositoryMap)

	got, err := scanner.Scan(context.Background(), &claircore.Layer{})
	if !errors.Is(err, wantErr) || len(got) != 1 || got[0] != packages[0] {
		t.Fatalf("Scan() = (%#v, %v), want original packages and error", got, err)
	}
	if packages[0].RepositoryHint != "repoid=old" {
		t.Errorf("error result was enriched: %q", packages[0].RepositoryHint)
	}
}

func TestMappedPackageScannerDelegatesIdentity(t *testing.T) {
	inner := &testPackageScanner{}
	scanner := NewMappedPackageScanner(inner, nil)
	if scanner.Name() != inner.Name() || scanner.Version() != inner.Version() || scanner.Kind() != inner.Kind() {
		t.Fatalf("identity was not delegated: %q/%q/%q", scanner.Name(), scanner.Version(), scanner.Kind())
	}
}

func TestMappedRHELEcosystemRegistration(t *testing.T) {
	ecosystem := mappedRHELEcosystem(context.Background())
	packages, err := ecosystem.PackageScanners(context.Background())
	if err != nil {
		t.Fatalf("PackageScanners() error = %v", err)
	}
	if len(packages) != 1 {
		t.Fatalf("package scanners = %d, want 1", len(packages))
	}
	if _, ok := packages[0].(*MappedPackageScanner); !ok {
		t.Fatalf("package scanner type = %T, want mapped wrapper", packages[0])
	}
	if packages[0].Name() != "rhel-package-scanner" {
		t.Errorf("package scanner name = %q", packages[0].Name())
	}

	dists, err := ecosystem.DistributionScanners(context.Background())
	if err != nil || len(dists) != 1 || dists[0].Name() != "rhel" {
		t.Fatalf("distribution scanners = %v, %v", dists, err)
	}
	repos, err := ecosystem.RepositoryScanners(context.Background())
	if err != nil || len(repos) != 1 || repos[0].Name() != "rhel-repository-scanner" {
		t.Fatalf("repository scanners = %v, %v", repos, err)
	}
	coalescer, err := ecosystem.Coalescer(context.Background())
	if err != nil {
		t.Fatalf("Coalescer() error = %v", err)
	}
	if _, ok := coalescer.(*rhel.Coalescer); !ok {
		t.Fatalf("coalescer type = %T, want *rhel.Coalescer", coalescer)
	}
}

func TestMappedPackageScannerAssociatesMappedPackage(t *testing.T) {
	pkg := &claircore.Package{Name: "mapped-baseos-package", ID: "package-id", PackageDB: "rpm", RepositoryHint: "checksum=abc"}
	scanner := NewMappedPackageScanner(&testPackageScanner{packages: []*claircore.Package{pkg}}, testPackageRepositoryMap)
	packages, err := scanner.Scan(context.Background(), &claircore.Layer{})
	if err != nil {
		t.Fatalf("Scan() error = %v", err)
	}

	repo := &claircore.Repository{ID: "repo-id", URI: "repoid=rhel-test-baseos"}
	report, err := (&rhel.Coalescer{}).Coalesce(context.Background(), []*indexer.LayerArtifacts{{Pkgs: packages, Repos: []*claircore.Repository{repo}}})
	if err != nil {
		t.Fatalf("Coalesce() error = %v", err)
	}
	if got := report.Environments[pkg.ID][0].RepositoryIDs; len(got) != 1 || got[0] != repo.ID {
		t.Fatalf("repository association = %v, want [%q]", got, repo.ID)
	}
}

func TestMappedPackageScannerUsesBroadAssociationForUnmappedPackage(t *testing.T) {
	pkg := &claircore.Package{Name: "offline-package", ID: "package-id", PackageDB: "rpm", RepositoryHint: "repoid=offline-repo&checksum=abc"}
	scanner := NewMappedPackageScanner(&testPackageScanner{packages: []*claircore.Package{pkg}}, testPackageRepositoryMap)
	packages, err := scanner.Scan(context.Background(), &claircore.Layer{})
	if err != nil {
		t.Fatalf("Scan() error = %v", err)
	}

	repo := &claircore.Repository{ID: "repo-id", URI: "repoid=rhel-test-baseos"}
	report, err := (&rhel.Coalescer{}).Coalesce(context.Background(), []*indexer.LayerArtifacts{{Pkgs: packages, Repos: []*claircore.Repository{repo}}})
	if err != nil {
		t.Fatalf("Coalesce() error = %v", err)
	}
	if got := report.Environments[pkg.ID][0].RepositoryIDs; len(got) != 1 || got[0] != repo.ID {
		t.Fatalf("repository association = %v, want broad association [%q]", got, repo.ID)
	}
	assertHint(t, pkg.RepositoryHint, map[string]string{"checksum": "abc"})
}

func assertHint(t *testing.T, raw string, want map[string]string) {
	t.Helper()
	got, err := url.ParseQuery(raw)
	if err != nil {
		t.Fatalf("ParseQuery(%q): %v", raw, err)
	}
	if len(got) != len(want) {
		t.Fatalf("hint %q has %d values, want %d", raw, len(got), len(want))
	}
	for key, value := range want {
		if got.Get(key) != value {
			t.Errorf("hint %q %s = %q, want %q", raw, key, got.Get(key), value)
		}
	}
}
