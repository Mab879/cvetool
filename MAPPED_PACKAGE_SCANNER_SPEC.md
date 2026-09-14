# Mapped RHEL Package Scanner

## Purpose

Prevent RHEL package false-negatives caused by installer-derived package records
that do not contain a usable DNF `repoid`.

The existing RHEL package scanner remains responsible for discovering installed
packages. A consumer-owned wrapper will enrich packages whose repository hint is
missing, allowing the existing RHEL repository scanner and coalescer to associate
the package with the repository normally.

## Scope

This change is implemented entirely in the library consumer.

It must not modify:

- Claircore's RHEL package scanner.
- Claircore's DNF handling.
- Claircore's RHEL repository scanner.
- Claircore's RHEL coalescer.

The package-name-to-repository mapping loader may initially be a stub. The
mapping itself is treated as authoritative for this implementation.

## Required Behavior

The wrapper must implement `indexer.PackageScanner` and wrap the existing RHEL
package scanner.

For every package returned by the wrapped scanner:

1. Parse `Package.RepositoryHint` with `url.ParseQuery`.
2. If the parsed hint contains a non-empty `repoid`, preserve the package
   unchanged.
3. Otherwise, look up the package name in the package-to-repository mapping.
4. If a mapping exists, set `repoid` with `url.Values.Set` and serialize the
   complete hint with `url.Values.Encode`.
5. If no mapping exists, leave the package unchanged.

Existing hint values, including RPM hashes and signing-key values, must remain
present and unchanged in meaning. The wrapper must not alter package order,
package pointers, or any package fields other than the intended repository hint
update.

If `url.ParseQuery` reports an error, the wrapper must leave that package's hint
unchanged. It must not fabricate a replacement hint or discard the package.

The wrapper must propagate errors from the wrapped scanner without modification
of the returned package list.

## Mapping Invariant

The mapping is authoritative. Every mapped repository ID must correspond to a
repository that the consumer's RHEL repository scanner returns for the relevant
layer and mapping data.

The mapping value must be the repository's DNF-style `repoid`, not its internal
`claircore.Repository.ID`. The RHEL coalescer compares the package hint's
`repoid` with the `repoid` query value in `Repository.URI`.

The initial design uses one repository ID per package name. Supporting multiple
candidate repositories, version-aware mappings, architecture-aware mappings, or
layer-time candidate intersection is out of scope. Those require a separately
defined mapping contract.

## Scanner Interface and Identity

Because `indexer.PackageScanner` also requires `Name`, `Version`, and `Kind`, the
wrapper must implement and delegate all three methods to the wrapped scanner in
addition to delegating `Scan`.

Delegating scanner identity is required so that libindex registration, scanner
deduplication, persisted scanner metadata, and indexer state tracking continue
to behave as they do for the underlying RHEL scanner.

## Registration

The consumer must construct the normal RHEL ecosystem and replace only its
package scanner registration:

- Keep the RHEL distribution scanner.
- Keep the RHEL repository scanner.
- Keep the RHEL coalescer.
- Replace the stock RHEL package scanner with the mapped wrapper.

The wrapper must not be registered alongside the original package scanner, since
that would run both scanners and could create duplicate package scanner entries.

## Fallback Policy

The default fallback policy is to leave packages unchanged when:

- The package name is not present in the mapping.
- The package hint cannot be parsed.
- The mapping produces no repository ID.

This preserves existing Claircore behavior for packages without a usable
repository hint. In particular, the unchanged package remains subject to the
RHEL coalescer's existing fallback association behavior.

An existing non-empty `repoid` is considered authoritative and must not be
overwritten, even if it does not match a repository returned for the layer.
Repairing invalid or stale existing IDs is not part of this change.

## Proposed Shape

The concrete type should be equivalent to:

```go
type MappedPackageScanner struct {
    inner  indexer.PackageScanner
    byName map[string]string
}
```

`Scan` should call `inner.Scan` first, then enrich the returned package slice in
place. It should use `url.ParseQuery` and `url.Values.Set`/`Encode`, never manual
query-string concatenation.

The implementation should defensively skip nil package pointers if the wrapped
scanner returns one, rather than panicking.

## Tests

Add focused wrapper tests covering:

- An existing DNF `repoid` is preserved.
- A missing `repoid` is populated from the package-name mapping.
- Existing hash and signing-key hint fields are preserved.
- An unmapped package is unchanged.
- A malformed hint is unchanged according to the fallback policy.
- Wrapped scanner errors are propagated.
- `Name`, `Version`, and `Kind` delegate to the wrapped scanner.
- The wrapper preserves package order and all unrelated package fields.

Add registration coverage proving that:

- The configured RHEL package scanner is the wrapper.
- The original RHEL repository scanner remains configured.
- The original RHEL distribution scanner remains configured.
- The original RHEL coalescer remains configured.
- The stock package scanner is not registered in parallel with the wrapper.

Add an end-to-end regression test for the false-negative:

1. The package scanner returns an installed package with no `repoid`.
2. The authoritative mapping maps that package name to a repository ID.
3. The RHEL repository scanner returns that repository with the same `repoid` in
   its URI.
4. The RHEL coalescer receives the enriched package and repository.
5. The resulting package environment contains the expected repository ID.

This test must verify the final package-to-repository association, not only that
the wrapper changed the hint string.

## Acceptance Criteria

- Packages with missing installer repository IDs can be associated with their
  mapped RHEL repository.
- Existing repository hints and package metadata are preserved.
- Packages without mappings retain the documented fallback behavior.
- Scanner errors are not swallowed.
- The consumer's RHEL ecosystem still uses the existing repository scanner,
  distribution scanner, and coalescer.
- No Claircore source or behavior is modified.
- The full project test suite passes.
