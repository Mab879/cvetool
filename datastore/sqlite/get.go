package sqlite

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"strings"
	"time"

	"github.com/google/uuid"
	"github.com/quay/claircore"
	"github.com/quay/claircore/datastore"
	"github.com/quay/claircore/libvuln/driver"
	"github.com/quay/zlog"
)

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

	if err := tx.Commit(); err != nil {
		return nil, fmt.Errorf("failed to commit tx: %v", err)
	}

	return results, nil
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
