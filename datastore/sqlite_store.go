package datastore

import (
	"bytes"
	"context"
	"crypto/md5"
	"database/sql"
	sqldriver "database/sql/driver"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"sort"
	"strconv"
	"strings"
	"time"

	migrations "github.com/ComplianceAsCode/cvetool/migrations"
	"github.com/google/uuid"
	version "github.com/hashicorp/go-version"
	"github.com/jackc/pgx/v5"
	"github.com/quay/claircore"
	"github.com/quay/claircore/datastore"
	"github.com/quay/claircore/libvuln/driver"
	"github.com/quay/zlog"
	"github.com/remind101/migrate"
	"modernc.org/sqlite"
)

// compile check datastore.MatcherStore implementation
var _ datastore.MatcherStore = (*sqliteMatcherStore)(nil)

type intVersion [10]int32

func (v *intVersion) String() string {
	var strs []string
	for _, p := range v {
		strs = append(strs, fmt.Sprint(p))
	}
	return strings.Join(strs, ".")
}

func (v *intVersion) FromString(str string) error {
	str = strings.Trim(str, "{}")
	sl := strings.Split(str, ",")
	for i := range sl {
		p, err := strconv.ParseInt(sl[i], 10, 32)
		if err != nil {
			return err
		}
		v[i] = int32(p)
	}
	return nil
}

func NewSQLiteMatcherStore(DSN string, doMigration bool) (*sqliteMatcherStore, error) {
	sqlite.MustRegisterDeterministicScalarFunction("version_in", 2, _sqliteVersionIn)
	db, err := sql.Open("sqlite", DSN)
	if err != nil {
		return nil, err
	}

	if doMigration {
		migrator := migrate.NewMigrator(db)
		migrator.Table = migrations.MigrationTable
		if err := migrator.Exec(migrate.Up, migrations.MatcherMigrations...); err != nil {
			return nil, err
		}
	}
	return &sqliteMatcherStore{conn: db}, nil
}

// _sqliteVersionIn is registered and used to determine if a package version falls within a version
// range, the lower bound is considered inclusive and the upper is considered exclusive.

// vulnerable range is expected as a pair of 10 part, comma seperated version representations
// separated by `__` e.g. "{0,0,0,0,0,0,0,0,0,0}__{3,6,2147483647,0,0,0,0,0,0,0}"
func _sqliteVersionIn(ctx *sqlite.FunctionContext, args []sqldriver.Value) (sqldriver.Value, error) {
	if len(args) != 2 {
		return nil, errors.New("version_in must be passed 2 args")
	}
	pkgVer, ok := args[0].(string)
	if !ok {
		return nil, errors.New("could not convert package version arg to string")
	}
	vulnRange, ok := args[1].(string)
	if !ok {
		return nil, errors.New("could not convert vulnerable range arg to string")
	}

	var lower, upper intVersion
	ver, err := version.NewVersion(pkgVer)
	if err != nil {
		return false, fmt.Errorf("could not create version: %v", err)
	}

	vers := strings.Split(vulnRange, "__")
	if len(vers) != 2 {
		return false, fmt.Errorf("invalid version range %s", vulnRange)
	}
	err = lower.FromString(vers[0])
	if err != nil {
		return false, fmt.Errorf("could not create lower version: %v", err)
	}
	err = upper.FromString(vers[1])
	if err != nil {
		return false, fmt.Errorf("could not create upper version: %v", err)
	}
	constraints, err := version.NewConstraint(">=" + lower.String() + ", < " + upper.String())
	if err != nil {
		return false, fmt.Errorf("could not compare versions: %v", err)
	}
	if constraints.Check(ver) {
		return true, nil
	}
	return false, nil
}

type sqliteMatcherStore struct {
	conn *sql.DB
}

// UpdateEnrichments creates a new EnrichmentUpdateOperation, inserts the provided
// EnrichmentRecord(s), and ensures enrichments from previous updates are not
// queries by clients.
func (ms *sqliteMatcherStore) UpdateEnrichments(ctx context.Context, updaterName string, fp driver.Fingerprint, es []driver.EnrichmentRecord) (uuid.UUID, error) {
	esIter := func(yield func(*driver.EnrichmentRecord, error) bool) {
		for i := range es {
			if !yield(&es[i], nil) {
				break
			}
		}
	}

	return ms.UpdateEnrichmentsIter(ctx, updaterName, fp, esIter)
}

// UpdateEnrichmentsIter performs the same operation as UpdateEnrichments, but
// accepting an iterator function.
func (ms *sqliteMatcherStore) UpdateEnrichmentsIter(ctx context.Context, updaterName string, fp driver.Fingerprint, enIter datastore.EnrichmentIter) (uuid.UUID, error) {
	const (
		create = `
			INSERT
			INTO
				update_operation (updater, fingerprint, kind, ref)
			VALUES
				($1, $2, 'enrichment', $3)
			RETURNING
				id;`
		insert = `
			INSERT
			INTO
				enrichment (hash_kind, hash, updater, tags, data)
			VALUES
				($1, $2, $3, json_array($4), $5)
			ON CONFLICT
				(hash_kind, hash)
			DO NOTHING;`
		assoc = `
			INSERT
			INTO
				uo_enrich (enrich, updater, uo)
			VALUES
			(
				(
					SELECT
						id
					FROM
						enrichment
					WHERE
						hash_kind = $1
						AND hash = $2
				),
				$3,
				$4
			)
			ON CONFLICT DO NOTHING;`
	)

	var ref = uuid.New()
	var id uint64
	var enCt int

	tx, err := ms.conn.BeginTx(ctx, &sql.TxOptions{})
	if err != nil {
		return uuid.Nil, err
	}
	defer tx.Rollback()

	if err := tx.QueryRowContext(ctx, create, updaterName, string(fp), ref.String()).Scan(&id); err != nil {
		return uuid.Nil, fmt.Errorf("failed to create update_operation: %w", err)
	}
	zlog.Debug(ctx).
		Str("ref", ref.String()).
		Msg("update_operation created")

	enIter(func(es *driver.EnrichmentRecord, iterErr error) bool {
		if iterErr != nil {
			err = fmt.Errorf("iterating on enrichments: %w", iterErr)
			return false
		}
		enCt++

		hashKind, hash := hashEnrichment(es)
		_, err = tx.ExecContext(ctx, insert,
			hashKind, hash, updaterName, strings.Join(es.Tags, ","), es.Enrichment,
		)
		if err != nil {
			zlog.Error(ctx).Err(err)
			err = fmt.Errorf("failed to insert enrichment: %w", err)
			return false
		}

		_, err = tx.ExecContext(ctx, assoc,
			hashKind, hash, updaterName, id,
		)
		if err != nil {
			zlog.Error(ctx).Err(err)
			err = fmt.Errorf("failed to assoc enrichment: %w", err)
			return false
		}

		return true
	})

	if err != nil {
		return uuid.Nil, err
	}

	if err := tx.Commit(); err != nil {
		return uuid.Nil, fmt.Errorf("failed to commit transaction: %w", err)
	}

	if _, err = ms.conn.ExecContext(ctx, "ANALYZE enrichment"); err != nil {
		zlog.Error(ctx).Err(err)
		return uuid.Nil, fmt.Errorf("could not ANALYZE enrichment: %w", err)
	}

	zlog.Debug(ctx).
		Stringer("ref", ref).
		Int("inserted", enCt).
		Msg("update_operation committed")

	return ref, nil
}

func hashEnrichment(r *driver.EnrichmentRecord) (k string, d []byte) {
	h := md5.New()
	sort.Strings(r.Tags)
	for _, t := range r.Tags {
		io.WriteString(h, t)
		h.Write([]byte("\x00"))
	}
	h.Write(r.Enrichment)
	return "md5", h.Sum(nil)
}

func getMetadata(ctx context.Context, tx *sql.Tx, kind string, val string) (int64, error) {
	var metadataID int64
	s := md5.Sum([]byte(val))
	const (
		get = `
		SELECT id FROM metadata
		WHERE kind = $1
		AND hash_kind = $2
		AND hash = $3`
		insert = `
		INSERT INTO metadata (
			kind, hash_kind, hash, value
		) VALUES (
			$1, $2, $3, $4
		)
		ON CONFLICT (kind, hash_kind, hash) DO NOTHING
		RETURNING id;`
	)
	err := tx.QueryRowContext(ctx, get, kind, "md5", s[:], val).Scan(&metadataID)
	switch {
	case err == sql.ErrNoRows:
		if err := tx.QueryRowContext(ctx, insert, kind, "md5", s[:], val).Scan(&metadataID); err != nil {
			return 0, fmt.Errorf("failed to scan description: %v", err)
		}
	case err != nil:
		return 0, err
	}
	return metadataID, nil
}

// UpdateVulnerabilities creates a new UpdateOperation, inserts the provided
// vulnerabilities, and ensures vulnerabilities from previous updates are
// not queried by clients.
func (ms *sqliteMatcherStore) UpdateVulnerabilities(ctx context.Context, updaterName string, fp driver.Fingerprint, vs []*claircore.Vulnerability) (uuid.UUID, error) {
	zlog.Debug(ctx).Msg(">>> UpdateVulnerabilities")
	vsIter := func(yield func(*claircore.Vulnerability, error) bool) {
		for i := range vs {
			if !yield(vs[i], nil) {
				break
			}
		}
	}

	return ms.UpdateVulnerabilitiesIter(ctx, updaterName, fp, vsIter)
}

// UpdateVulnerabilitiesIter performs the same operation as
// UpdateVulnerabilities, but accepting an iterator function.
func (ms *sqliteMatcherStore) UpdateVulnerabilitiesIter(ctx context.Context, updater string, fp driver.Fingerprint, vsIter datastore.VulnerabilityIter) (uuid.UUID, error) {
	return ms.updateVulnerabilities(ctx, updater, fp, vsIter, nil)
}

func (ms *sqliteMatcherStore) updateVulnerabilities(ctx context.Context, updater string, fingerprint driver.Fingerprint, vulnIter datastore.VulnerabilityIter, delIter datastore.Iter[string]) (uuid.UUID, error) {
	const (
		// Create makes a new update operation and returns the reference and ID.
		create = `INSERT INTO update_operation (updater, fingerprint, kind, ref) VALUES ($1, $2, 'vulnerability', $3) RETURNING id;`
		// Select existing vulnerabilities that are associated with the latest_update_operation.
		selectExisting = `
		SELECT
			"name",
			"vuln"."id"
		FROM
			"vuln"
			INNER JOIN "uo_vuln" ON ("vuln"."id" = "uo_vuln"."vuln")
			INNER JOIN "latest_update_operations" ON (
			"latest_update_operations"."id" = "uo_vuln"."uo"
			)
		WHERE
			(
			"latest_update_operations"."kind" = 'vulnerability'
			)
		AND
			(
			"vuln"."updater" = $1
			)`
		// assocExisting associates existing vulnerabilities with new update operations
		assocExisting = `INSERT INTO uo_vuln (uo, vuln) VALUES ($1, $2) ON CONFLICT DO NOTHING;`
		// Insert attempts to create a new vulnerability. It fails silently.
		insert = `
		INSERT INTO vuln (
			hash_kind, hash,
			updater, issued, links, severity, normalized_severity,
			package_name, package_version, package_module, package_arch, package_kind,
			dist_id, dist_name, dist_version, dist_version_code_name, dist_version_id, dist_arch, dist_cpe, dist_pretty_name,
			repo_name, repo_key, repo_uri,
			fixed_in_version, arch_operation, version_kind, vulnerable_range, description_id, name_id
		) VALUES (
		  $1, $2,
		  $3, $4, $5, $6, $7, $8, $9,
		  $10, $11, $12, $13, $14,
		  $15, $16, $17, $18, $19, $20, $21, $22,
		  $23, $24, $25,
		  $26, $27, $28, $29
		)
		ON CONFLICT (hash_kind, hash) DO NOTHING;`
		assoc = `
		INSERT INTO uo_vuln (uo, vuln) VALUES (
			$3,
			(SELECT id FROM vuln WHERE hash_kind = $1 AND hash = $2))
		ON CONFLICT DO NOTHING;`
	)

	var uoID uint64
	var ref = uuid.New()

	tx, err := ms.conn.BeginTx(ctx, &sql.TxOptions{})
	if err != nil {
		return uuid.Nil, err
	}
	defer tx.Rollback()

	delta := delIter != nil
	oldVulns := make(map[string][]string)

	if delta {
		zlog.Debug(ctx).Msg("updateVulnerabilities (delta, get)")
		// Get existing vulns
		rows, err := ms.conn.QueryContext(ctx, selectExisting, updater)
		if err != nil {
			return uuid.Nil, fmt.Errorf("failed to get existing vulns: %w", err)
		}
		defer rows.Close()

		for rows.Next() {
			var tmpID int64
			var ID, name string
			err := rows.Scan(
				&name,
				&tmpID,
			)

			ID = strconv.FormatInt(tmpID, 10)
			if err != nil {
				return uuid.Nil, fmt.Errorf("failed to scan vulnerability: %w", err)
			}
			oldVulns[name] = append(oldVulns[name], ID)
		}
		if err := rows.Err(); err != nil {
			return uuid.Nil, fmt.Errorf("error reading existing vulnerabilities: %w", err)
		}

		if len(oldVulns) > 0 {
			vulnIter(func(v *claircore.Vulnerability, _ error) bool {
				// If we have an existing vuln in the new batch
				// delete it from the oldVulns map so it doesn't
				// get associated with the new update_operation.
				delete(oldVulns, v.Name)
				return true
			})
			delIter(func(delName string, _ error) bool {
				// If we have an existing vuln that has been signaled
				// as deleted by the updater then delete it so it doesn't
				// get associated with the new update_operation.
				delete(oldVulns, delName)
				return true
			})
		}
	}

	// Create new update operation
	if err := tx.QueryRowContext(ctx, create, updater, fingerprint, ref.String()).Scan(&uoID); err != nil {
		zlog.Error(ctx).Err(err)
		return uuid.Nil, fmt.Errorf("failed to create update_operation: %w", err)
	}
	zlog.Debug(ctx).
		Str("ref", ref.String()).
		Msg("created update operation")

	if delta {
		zlog.Debug(ctx).Msg("updateVulnerabilities (delta, assoc)")
		// Associate already existing vulnerabilities with new update_operation.
		for _, vs := range oldVulns {
			for _, vID := range vs {
				_, err := tx.ExecContext(ctx, assocExisting, uoID, vID)
				if err != nil {
					return uuid.Nil, fmt.Errorf("could not update old vulnerability with new UO: %w", err)
				}
			}
		}
	}

	skipCt := 0
	vulnCt := 0

	vulnIter(func(vuln *claircore.Vulnerability, iterErr error) bool {
		if iterErr != nil {
			err = fmt.Errorf("iterating on vulnerabilities: %w", iterErr)
			return false
		}

		// Get or save description
		var descID int64
		descID, err = getMetadata(ctx, tx, "description", vuln.Description)
		if err != nil {
			err = fmt.Errorf("failed to get description: %w", err)
			return false
		}
		var nameID int64
		nameID, err = getMetadata(ctx, tx, "name", vuln.Name)
		if err != nil {
			err = fmt.Errorf("failed to get name: %w", err)
			return false
		}
		vulnCt++
		if vuln.Package == nil || vuln.Package.Name == "" {
			skipCt++
			return true
		}

		pkg := vuln.Package
		dist := vuln.Dist
		repo := vuln.Repo
		if dist == nil {
			dist = &claircore.Distribution{}
		}
		if repo == nil {
			repo = &claircore.Repository{}
		}
		hashKind, hash := md5Vuln(vuln)
		vKind, vrLower, vrUpper := rangefmt(vuln.Range)

		if _, err = tx.ExecContext(ctx, insert,
			hashKind, hash,
			vuln.Updater, vuln.Issued.Format(time.RFC3339), vuln.Links, vuln.Severity, vuln.NormalizedSeverity,
			pkg.Name, pkg.Version, pkg.Module, pkg.Arch, pkg.Kind,
			dist.DID, dist.Name, dist.Version, dist.VersionCodeName, dist.VersionID, dist.Arch, &dist.CPE, dist.PrettyName,
			repo.Name, repo.Key, repo.URI,
			vuln.FixedInVersion, vuln.ArchOperation, vKind, strings.Join([]string{vrLower, vrUpper}, "__"), descID, nameID,
		); err != nil {
			err = fmt.Errorf("failed to insert vulnerability: %w", err)
			return false
		}
		if _, err = tx.ExecContext(ctx, assoc, hashKind, hash, uoID); err != nil {
			err = fmt.Errorf("failed to assoc vulnerability: %w", err)
			return false
		}

		return true
	})

	if err != nil {
		return uuid.Nil, err
	}

	if err := tx.Commit(); err != nil {
		return uuid.Nil, fmt.Errorf("failed to commit transaction: %w", err)
	}

	zlog.Debug(ctx).
		Str("ref", ref.String()).
		Int("skipped", skipCt).
		Int("inserted", vulnCt-skipCt).
		Msg("update_operation committed")

	return ref, nil
}

// Md5Vuln creates an md5 hash from the members of the passed-in Vulnerability,
// giving us a stable, context-free identifier for this revision of the
// Vulnerability.
func md5Vuln(v *claircore.Vulnerability) (string, []byte) {
	var b bytes.Buffer
	b.WriteString(v.Name)
	b.WriteString(v.Description)
	b.WriteString(v.Issued.String())
	b.WriteString(v.Links)
	b.WriteString(v.Severity)
	if v.Package != nil {
		b.WriteString(v.Package.Name)
		b.WriteString(v.Package.Version)
		b.WriteString(v.Package.Module)
		b.WriteString(v.Package.Arch)
		b.WriteString(v.Package.Kind)
	}
	if v.Dist != nil {
		b.WriteString(v.Dist.DID)
		b.WriteString(v.Dist.Name)
		b.WriteString(v.Dist.Version)
		b.WriteString(v.Dist.VersionCodeName)
		b.WriteString(v.Dist.VersionID)
		b.WriteString(v.Dist.Arch)
		b.WriteString(v.Dist.CPE.BindFS())
		b.WriteString(v.Dist.PrettyName)
	}
	if v.Repo != nil {
		b.WriteString(v.Repo.Name)
		b.WriteString(v.Repo.Key)
		b.WriteString(v.Repo.URI)
	}
	b.WriteString(v.ArchOperation.String())
	b.WriteString(v.FixedInVersion)
	if k, l, u := rangefmt(v.Range); k != nil {
		b.WriteString(*k)
		b.WriteString(l)
		b.WriteString(u)
	}
	s := md5.Sum(b.Bytes())
	return "md5", s[:]
}

func rangefmt(r *claircore.Range) (kind *string, lower, upper string) {
	lower, upper = "{}", "{}"
	if r == nil || r.Lower.Kind != r.Upper.Kind {
		return kind, lower, upper
	}

	kind = &r.Lower.Kind // Just tested the both kinds are the same.
	v := &r.Lower
	var buf strings.Builder
	b := make([]byte, 0, 16) // 16 byte wide scratch buffer

	buf.WriteByte('{')
	for i := range 10 {
		if i != 0 {
			buf.WriteByte(',')
		}
		buf.Write(strconv.AppendInt(b, int64(v.V[i]), 10))
	}
	buf.WriteByte('}')
	lower = buf.String()
	buf.Reset()
	v = &r.Upper
	buf.WriteByte('{')
	for i := range 10 {
		if i != 0 {
			buf.WriteByte(',')
		}
		buf.Write(strconv.AppendInt(b, int64(v.V[i]), 10))
	}
	buf.WriteByte('}')
	upper = buf.String()

	return kind, lower, upper
}

// Initialized reports whether the vulnstore contains vulnerabilities.
func (ms *sqliteMatcherStore) Initialized(_ context.Context) (bool, error) {
	return true, nil
}

// get finds the vulnerabilities which match each package provided in the packages array
// this maybe a one to many relationship. each package is assumed to have an ID.
// a map of Package.ID => Vulnerabilities is returned.
func (ms *sqliteMatcherStore) Get(ctx context.Context, records []*claircore.IndexRecord, opts datastore.GetOpts) (map[string][]*claircore.Vulnerability, error) {
	zlog.Debug(ctx).Msg(">>> sqliteMatcherStore.Get")

	tx, err := ms.conn.BeginTx(ctx, nil)
	if err != nil {
		return nil, err
	}
	defer tx.Rollback()
	results := make(map[string][]*claircore.Vulnerability)
	vulnSet := make(map[string]map[string]struct{})

	for _, record := range records {
		query, err := buildGetQuery(record, &opts)
		if err != nil {
			// if we cannot build a query for an individual record continue to the next
			zlog.Debug(ctx).
				Err(err).
				Str("record", fmt.Sprintf("%+v", record)).
				Msg("could not build query for record")
			continue
		}
		// queue the select query
		rows, err := tx.QueryContext(ctx, query)
		if err != nil {
			return nil, err
		}
		defer rows.Close()

		// unpack all returned rows into claircore.Vulnerability structs
		for rows.Next() {
			// fully allocate vuln struct
			v := &claircore.Vulnerability{
				Package: &claircore.Package{},
				Dist:    &claircore.Distribution{},
				Repo:    &claircore.Repository{},
			}

			var issued string
			var hashBin string
			err := rows.Scan(
				&hashBin,
				&v.Name,
				&v.Description,
				&issued,
				&v.Links,
				&v.Severity,
				&v.NormalizedSeverity,
				&v.Package.Name,
				&v.Package.Version,
				&v.Package.Module,
				&v.Package.Arch,
				&v.Package.Kind,
				&v.Dist.DID,
				&v.Dist.Name,
				&v.Dist.Version,
				&v.Dist.VersionCodeName,
				&v.Dist.VersionID,
				&v.Dist.Arch,
				&v.Dist.CPE,
				&v.Dist.PrettyName,
				&v.ArchOperation,
				&v.Repo.Name,
				&v.Repo.Key,
				&v.Repo.URI,
				&v.FixedInVersion,
				&v.Updater,
			)
			if err != nil {
				return nil, fmt.Errorf("failed to scan vulnerability: %v", err)
			}

			v.ID = base64.StdEncoding.EncodeToString([]byte(hashBin))

			v.Issued, err = time.Parse(time.RFC3339, issued)
			if err != nil {
				return nil, fmt.Errorf("failed parse issued date: %v", err)
			}

			rid := record.Package.ID
			if _, ok := vulnSet[rid]; !ok {
				vulnSet[rid] = make(map[string]struct{})
			}
			if _, ok := vulnSet[rid][v.ID]; !ok {
				vulnSet[rid][v.ID] = struct{}{}
				results[rid] = append(results[rid], v)
			}
		}
	}
	if err := tx.Commit(); err != nil {
		return nil, fmt.Errorf("failed to commit tx: %v", err)
	}
	return results, nil
}

func makePlaceholders(startIndex, length int) string {
	str := ""
	for i := startIndex; i < length+startIndex; i++ {
		str = str + fmt.Sprintf("$%d,", i)
	}
	return "(" + strings.TrimRight(str, ",") + ")"
}

func formatStringArray(s []string) string {
	return strings.Join(s, "','")
}

func (ms *sqliteMatcherStore) GetEnrichment(ctx context.Context, kind string, tags []string) ([]driver.EnrichmentRecord, error) {
	var query = `
	WITH
			latest
				AS (
					SELECT
						id
					FROM
						latest_update_operations
					WHERE
						updater = $1
					AND
						kind = 'enrichment'
					LIMIT 1
				)
	SELECT
		e.tags, e.data
	FROM
		enrichment AS e,
		uo_enrich AS uo,
		latest,
		json_each(e.tags)
	WHERE
		uo.uo = latest.id
		AND uo.enrich = e.id
		AND json_each.value IN ` + makePlaceholders(2, len(tags)) + ";"

	tx, err := ms.conn.BeginTx(ctx, nil)
	if err != nil {
		return nil, err
	}
	defer tx.Rollback()

	results := make([]driver.EnrichmentRecord, 0, 8) // Guess at capacity.
	args := []any{kind}
	for _, v := range tags {
		args = append(args, v)
	}
	rows, err := tx.QueryContext(ctx, query, args...)
	if err != nil {
		zlog.Error(ctx).Err(err)
		return nil, err
	}
	defer rows.Close()
	i := 0
	for rows.Next() {
		results = append(results, driver.EnrichmentRecord{})
		r := &results[i]
		var tags = []byte{}
		if err := rows.Scan(&tags, &r.Enrichment); err != nil {
			return nil, err
		}
		if err := json.Unmarshal(tags, &r.Tags); err != nil {
			return nil, err
		}
		i++
	}
	if err := rows.Err(); err != nil {
		return nil, err
	}
	return results, nil
}

// GetUpdateOperations returns a list of UpdateOperations in date descending
// order for the given updaters.
//
// The returned map is keyed by Updater implementation's unique names.
//
// If no updaters are specified, all UpdateOperations are returned.
func (ms *sqliteMatcherStore) GetUpdateOperations(ctx context.Context, kind driver.UpdateKind, updater ...string) (map[string][]driver.UpdateOperation, error) {
	const (
		query              = `SELECT ref, updater, fingerprint, date FROM update_operation WHERE updater IN ($1) ORDER BY id DESC;`
		queryVulnerability = `SELECT ref, updater, fingerprint, date FROM update_operation WHERE updater IN ($1) AND kind = 'vulnerability' ORDER BY id DESC;`
		queryEnrichment    = `SELECT ref, updater, fingerprint, date FROM update_operation WHERE updater IN ($1) AND kind = 'enrichment' ORDER BY id DESC;`
		getUpdaters        = `SELECT DISTINCT(updater) FROM update_operation;`
	)

	tx, err := ms.conn.BeginTx(ctx, nil)
	if err != nil {
		return nil, fmt.Errorf("failed to begin transaction: %w", err)
	}
	defer tx.Rollback()
	out := make(map[string][]driver.UpdateOperation)

	// Get distinct updaters from database if nothing specified.
	if len(updater) == 0 {
		updater = []string{}

		rows, err := tx.QueryContext(ctx, getUpdaters)
		switch {
		case err == nil:
		case errors.Is(err, pgx.ErrNoRows):
			return out, nil
		default:
			return nil, fmt.Errorf("failed to get distinct updates: %w", err)
		}

		defer rows.Close() // OK to defer and call, as per docs.

		for rows.Next() {
			var u string
			err := rows.Scan(&u)
			if err != nil {
				return nil, fmt.Errorf("failed to scan updater: %w", err)
			}
			updater = append(updater, u)
		}
		if err := rows.Err(); err != nil {
			return nil, err
		}
		rows.Close()
	}

	var q string
	switch kind {
	case "":
		q = query
	case driver.EnrichmentKind:
		q = queryEnrichment
	case driver.VulnerabilityKind:
		q = queryVulnerability
	}

	rows, err := tx.QueryContext(ctx, q, formatStringArray(updater))
	switch {
	case err == nil:
	case errors.Is(err, pgx.ErrNoRows):
		return out, nil
	default:
		return nil, fmt.Errorf("failed to get distinct updates: %w", err)
	}
	defer rows.Close()

	for rows.Next() {
		var uo driver.UpdateOperation
		err := rows.Scan(
			&uo.Ref,
			&uo.Updater,
			&uo.Fingerprint,
			&uo.Date,
		)
		if err != nil {
			zlog.Error(ctx).Err(err)
			return nil, fmt.Errorf("failed to scan update operation for updater %q: %w", uo.Updater, err)
		}
		out[uo.Updater] = append(out[uo.Updater], uo)
	}
	if err := rows.Err(); err != nil {
		return nil, err
	}

	return out, nil
}

// GetLatestUpdateRefs reports the latest update reference for every known
// updater.
func (ms *sqliteMatcherStore) GetLatestUpdateRefs(ctx context.Context, kind driver.UpdateKind) (map[string][]driver.UpdateOperation, error) {
	panic("GetLatestUpdateRefs is not implemented!")
}

// GetLatestUpdateRef reports the latest update reference of any known
// updater.
func (ms *sqliteMatcherStore) GetLatestUpdateRef(ctx context.Context, kind driver.UpdateKind) (uuid.UUID, error) {
	panic("GetLatestUpdateRef is not implemented!")
}

// GetUpdateOperationDiff reports the UpdateDiff of the two referenced
// Operations.
//
// In diff(1) terms, this is like
//
//	diff prev cur
func (ms *sqliteMatcherStore) GetUpdateDiff(ctx context.Context, prev uuid.UUID, cur uuid.UUID) (*driver.UpdateDiff, error) {
	zlog.Warn(ctx).Msg("sqliteMatcherStore.GetUpdateDiff is not implemented!")
	return nil, nil
}

// GC stuff
// DeleteUpdateOperations removes an UpdateOperation.
// A call to GC must be run after this to garbage collect vulnerabilities associated
// with the UpdateOperation.
//
// The number of UpdateOperations deleted is returned.
func (ms *sqliteMatcherStore) DeleteUpdateOperations(ctx context.Context, uuids ...uuid.UUID) (int64, error) {
	zlog.Warn(ctx).Msg("sqliteMatcherStore.DeleteUpdateOperations is not implemented!")
	return 0, nil
}

// GC will delete any update operations for an updater which exceeds the provided keep
// value.
//
// Implementations may throttle the GC process for datastore efficiency reasons.
//
// The returned int64 value indicates the remaining number of update operations needing GC.
// Running this method till the returned value is 0 accomplishes a full GC of the vulnstore.
func (ms *sqliteMatcherStore) GC(ctx context.Context, count int) (int64, error) {
	zlog.Warn(ctx).Msg("sqliteMatcherStore.GC is not implemented!")
	return 0, nil
}

func (ms *sqliteMatcherStore) VacuumDatabase(ctx context.Context) error {
	zlog.Debug(ctx).Msg(">>> VacuumDatabase")
	const (
		vacuum = "VACUUM;"
	)
	_, err := ms.conn.Exec(vacuum)
	if err != nil {
		return fmt.Errorf("failed to vacuum database: %v", err)
	}
	zlog.Info(ctx).Msg("finished database vacuum")
	return nil
}

// RecordUpdaterStatus records that an updater is up to date with vulnerabilities at this time
func (ms *sqliteMatcherStore) RecordUpdaterStatus(ctx context.Context, updaterName string, updateTime time.Time, fingerprint driver.Fingerprint, updaterError error) error {
	zlog.Debug(ctx).Msg(">>> RecordUpdaterStatus")
	const (
		// upsertSuccessfulUpdate inserts or updates a record of the last time an updater successfully checked for new vulns
		upsertSuccessfulUpdate = `INSERT INTO updater_status (
			updater_name,
			last_attempt,
			last_success,
			last_run_succeeded,
			last_attempt_fingerprint
		) VALUES (
			$1,
			$2,
			$2,
			'true',
			$3
		)
		ON CONFLICT (updater_name) DO UPDATE
		SET last_attempt = $2,
			last_success = $2,
			last_run_succeeded = 'true',
			last_attempt_fingerprint = $3
		RETURNING updater_name;`

		// upsertFailedUpdate inserts or updates a record of the last time an updater attempted but failed to check for new vulns
		upsertFailedUpdate = `INSERT INTO updater_status (
					updater_name,
					last_attempt,
					last_run_succeeded,
					last_attempt_fingerprint,
					last_error
				) VALUES (
					$1,
					$2,
					'false',
					$3,
					$4
				)
				ON CONFLICT (updater_name) DO UPDATE
				SET last_attempt = $2,
					last_run_succeeded = 'false',
					last_attempt_fingerprint = $3,
					last_error = $4
				RETURNING updater_name;`
	)

	ctx = zlog.ContextWithValues(ctx,
		"component", "internal/vulnstore/sqlite/recordUpdaterStatus")

	tx, err := ms.conn.BeginTx(ctx, nil)
	if err != nil {
		return fmt.Errorf("unable to start transaction: %w", err)
	}
	defer tx.Rollback()

	var returnedUpdaterName string

	if updaterError == nil {
		zlog.Debug(ctx).
			Str("updater", updaterName).
			Msg("recording successful update")
		_, err := tx.ExecContext(ctx, upsertSuccessfulUpdate, updaterName, updateTime, fingerprint)
		if err != nil {
			return fmt.Errorf("failed to upsert successful updater status: %w", err)
		}
	} else {
		zlog.Debug(ctx).
			Str("updater", updaterName).
			Msg("recording failed update")
		if err := tx.QueryRowContext(ctx, upsertFailedUpdate, updaterName, updateTime, fingerprint, updaterError.Error()).Scan(&returnedUpdaterName); err != nil {
			return fmt.Errorf("failed to upsert failed updater status: %w", err)
		}
	}

	if err := tx.Commit(); err != nil {
		return fmt.Errorf("failed to commit transaction: %w", err)
	}

	zlog.Debug(ctx).
		Str("updater", updaterName).
		Msg("updater status stored in database")

	return nil
}

// RecordUpdaterSetStatus records that all updaters from an updater set are up to date with vulnerabilities at this time
func (ms *sqliteMatcherStore) RecordUpdaterSetStatus(ctx context.Context, updaterSet string, updateTime time.Time) error {
	zlog.Debug(ctx).Msg(">>> RecordUpdaterSetStatus")
	const (
		update = `UPDATE updater_status
		SET last_attempt = $1,
			last_success = $1,
			last_run_succeeded = 'true'
		WHERE updater_name LIKE $2 || '%';`
	)

	ctx = zlog.ContextWithValues(ctx,
		"component", "internal/vulnstore/postgres/recordUpdaterSetStatus")

	tx, err := ms.conn.BeginTx(ctx, nil)
	if err != nil {
		return fmt.Errorf("unable to start transaction: %w", err)
	}
	defer tx.Rollback()

	tag, err := tx.ExecContext(ctx, update, updateTime, updaterSet)
	if err != nil {
		return fmt.Errorf("failed to update updater statuses for updater set %s: %w", updaterSet, err)
	}

	if err := tx.Commit(); err != nil {
		return fmt.Errorf("failed to commit transaction: %w", err)
	}

	ra, err := tag.RowsAffected()
	zlog.Debug(ctx).
		Str("factory", updaterSet).
		Int64("rowsAffected", ra).
		Msg("status updated for factory updaters")

	return nil
}

func (ms *sqliteMatcherStore) DeltaUpdateVulnerabilities(ctx context.Context, updater string, fp driver.Fingerprint, vulns []*claircore.Vulnerability, deletedVulns []string) (uuid.UUID, error) {
	zlog.Debug(ctx).Msg(">>> DeltaUpdateVulnerabilities")
	iterVulns := func(yield func(*claircore.Vulnerability, error) bool) {
		for i := range vulns {
			if !yield(vulns[i], nil) {
				break
			}
		}
	}
	delVulns := func(yield func(string, error) bool) {
		for _, s := range deletedVulns {
			if !yield(s, nil) {
				break
			}
		}
	}
	return ms.updateVulnerabilities(ctx, updater, fp, iterVulns, delVulns)
}
