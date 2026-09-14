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

For every non-nil package returned by the wrapped scanner:

1. Parse `Package.RepositoryHint` with `url.ParseQuery`.
2. If the package name is present in the mapping and the mapping produces a
   non-empty repository ID, set `repoid` with `url.Values.Set` and serialize the
   complete hint with `url.Values.Encode`. This overrides any existing
   `repoid`, including an installer-specific or non-standard value.
3. If the package name is not present in the mapping and the parsed hint
   contains a non-empty `repoid`, emit a warning, remove only `repoid`, and
   serialize the complete remaining hint with `url.Values.Encode`.
4. If the package name is not present in the mapping and the parsed hint does
   not contain a non-empty `repoid`, leave the package unchanged.

Removing an unmapped package's repository ID deliberately enables the RHEL
coalescer's broad fallback association instead of silently dropping the
package association. The package must not be discarded or skipped from
vulnerability scanning.

For successfully parsed hints, existing hint values other than `repoid`,
including RPM hashes and signing-key values, must remain present and unchanged
in meaning. The wrapper must not alter package order, non-nil package pointers,
or any package fields other than the intended repository hint update.

If `url.ParseQuery` reports an error, the wrapper must emit a warning containing
the package name and original hint, set the package's `RepositoryHint` to an
empty string, and continue. This deliberately forces the RHEL coalescer's
broad fallback association. The package must not be discarded.

The wrapper must propagate errors from the wrapped scanner without modification
of the returned package list. It must enrich packages only when the wrapped
scanner returns no error. If the wrapped scanner returns both packages and an
error, return those exact packages and the error without enriching them.

## Mapping Invariant

The mapping is authoritative for this implementation. Every mapped repository
ID must be a DNF-style ID used by the relevant RHEL repository data. Layer-time
repository intersection is out of scope.

The mapping value must be the repository's DNF-style `repoid`, not its internal
`claircore.Repository.ID`. The RHEL coalescer compares the package hint's
`repoid` with the `repoid` query value in `Repository.URI`.

The initial design uses one repository ID per package name. Supporting multiple
candidate repositories, version-aware mappings, or architecture-aware mappings
is out of scope. Those require a separately defined mapping contract.

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

- The package name is not present in the mapping and the hint has no non-empty
  `repoid`.
- The mapping produces no repository ID.

For a mapped package with a non-empty mapping value, the mapping is
authoritative and replaces any existing `repoid`, including a valid-looking,
installer-specific, stale, or non-standard value. For an unmapped package, an
existing non-empty `repoid` is treated as potentially custom or non-standard:
the wrapper must emit a warning, remove only `repoid`, and preserve all other
hint values. The resulting hint then remains subject to the RHEL coalescer's
existing fallback association behavior.

The warning must identify the package name and original repository hint or ID,
and should state that broad repository association is being used. The warning
is informational and must not fail the scan. For example:

```text
found unmapped package "fuzzy-bunny" with repository hint "fuzzy-repoid"; using broad repository association
```

This policy favors RHEL CVE coverage over silently dropping a package because
an installer, offline mirror, or custom repository used a non-standard ID.

If `url.ParseQuery` reports an error, the wrapper warns and clears the hint as
described above. This ensures that malformed installer data cannot leave a
partial `repoid` that prevents broad fallback association.

## Proposed Shape

The concrete type should be equivalent to:

```go
type MappedPackageScanner struct {
    inner  indexer.PackageScanner
    byName map[string]string
}
```

`Scan` should call `inner.Scan` first. If the wrapped scanner returns an error,
it must return the exact package slice and error without enrichment. Otherwise,
it should enrich the returned package slice in place, omitting nil entries as
specified above. It should use `url.ParseQuery` and `url.Values.Set`/`Encode`,
never manual query-string concatenation.

The implementation should defensively handle nil package pointers if the
wrapped scanner returns one. It must emit a warning and omit nil entries from
the returned slice before handing results to the rest of the indexer. The
relative order of all non-nil packages must remain unchanged.

## Tests

Add focused wrapper tests covering:

- An existing `repoid` for a mapped package is replaced by the authoritative
  mapping.
- An existing `repoid` for an unmapped package emits a warning and is removed.
- A missing `repoid` is populated from the package-name mapping.
- Existing hash and signing-key hint fields are preserved when a mapping
  replaces `repoid`.
- An unmapped package with no `repoid` is unchanged.
- A malformed hint emits a warning, is cleared, and receives broad fallback
  association.
- A nil package pointer emits a warning and is omitted from the returned slice.
- Wrapped scanner errors are propagated.
- Packages returned alongside a wrapped scanner error are returned unchanged.
- `Name`, `Version`, and `Kind` delegate to the wrapped scanner.
- The wrapper preserves package order and all unrelated package fields.

Add registration coverage proving that:

- The configured RHEL package scanner is the wrapper.
- The original RHEL repository scanner remains configured.
- The original RHEL distribution scanner remains configured.
- The original RHEL coalescer remains configured.
- The stock package scanner is not registered in parallel with the wrapper.

Add an end-to-end regression test for the false-negative:

1. The package scanner returns an installed package whose hint either has no
   `repoid` or contains an installer-specific `repoid`.
2. The authoritative mapping maps that package name to a repository ID.
3. The RHEL repository scanner returns that repository with the same `repoid` in
   its URI.
4. The RHEL coalescer receives the enriched package and repository.
5. The resulting package environment contains the expected repository ID.

This test must verify the final package-to-repository association, not only that
the wrapper changed the hint string.

Add an end-to-end coverage test for an unmapped or offline package:

1. The package scanner returns an unmapped package with an installer hint
   containing a non-standard `repoid`.
2. The wrapper emits the warning and removes only `repoid`.
3. The RHEL coalescer receives the package with its remaining hint values.
4. The final package environment contains a broad repository association rather
   than silently dropping the package.

## Acceptance Criteria

- Packages with missing installer repository IDs can be associated with their
  mapped RHEL repository.
- Existing package metadata and non-`repoid` hint values are preserved.
- Authoritative mappings override installer-specific `repoid` values.
- Unmapped packages with non-standard repository hints produce a warning and
  retain broad association coverage.
- Malformed hints produce a warning and retain broad association coverage.
- Nil package pointers do not reach the coalescer.
- Packages without mappings retain the documented fallback behavior.
- Scanner errors are not swallowed.
- The consumer's RHEL ecosystem still uses the existing repository scanner,
  distribution scanner, and coalescer.
- No Claircore source or behavior is modified.
- The full project test suite passes.

## Future Work

- Deduplicate or rate-limit warnings for repeated unmapped packages and
  malformed hints.
