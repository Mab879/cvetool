package sqlite

import (
	"context"
	"fmt"
	"strings"

	"github.com/google/uuid"
	"github.com/quay/claircore/libvuln/driver"
	"github.com/quay/zlog"
)

func formatStringArray(s []string) string {
	return strings.Join(s, "','")
}

func formatStringArrayFromUUIDs(uuids []uuid.UUID) string {
	var s []string
	for _, uuid := range uuids {
		s = append(s, uuid.String())
	}
	return strings.Join(s, "','")
}

// GC stuff
// DeleteUpdateOperations removes an UpdateOperation.
// A call to GC must be run after this to garbage collect vulnerabilities associated
// with the UpdateOperation.
//
// The number of UpdateOperations deleted is returned.
func (ms *sqliteMatcherStore) DeleteUpdateOperations(ctx context.Context, uuids ...uuid.UUID) (int64, error) {
	const query = `DELETE FROM update_operation WHERE ref IN ($1);`
	ctx = zlog.ContextWithValues(ctx, "component", "internal/vulnstore/sqlite/deleteUpdateOperations")

	if len(uuids) == 0 {
		return 0, nil
	}

	// FIXME: This is REALLY ugly!
	fmt_q := fmt.Sprintf(strings.Replace(query, "$1", "'%s'", 1), formatStringArrayFromUUIDs(uuids))
	tag, err := ms.conn.ExecContext(ctx, fmt_q)
	if err != nil {
		zlog.Error(ctx).Err(err).Msg("ExecContext")
		return 0, fmt.Errorf("failed to delete: %w", err)
	}

	return tag.RowsAffected()
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

	// FIXME: This is REALLY ugly!
	fmt_q := fmt.Sprintf(strings.Replace(q, "$1", "'%s'", 1), formatStringArray(updater))
	rows, err := tx.QueryContext(ctx, fmt_q)
	switch {
	case err == nil:
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
	if err := tx.Commit(); err != nil {
		return nil, fmt.Errorf("failed to commit tx: %v", err)
	}

	return out, nil
}
