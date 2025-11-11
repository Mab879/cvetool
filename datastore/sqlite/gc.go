package sqlite

import (
	"context"
	"database/sql"
	"encoding/json"
	"fmt"

	"github.com/google/uuid"
	"github.com/quay/claircore/libvuln/driver"
	"github.com/quay/zlog"
)

// GC will delete any update operations for an updater which exceeds the provided keep
// value.
//
// Implementations may throttle the GC process for datastore efficiency reasons.
//
// The returned int64 value indicates the remaining number of update operations needing GC.
// Running this method till the returned value is 0 accomplishes a full GC of the vulnstore.
func (ms *sqliteMatcherStore) GC(ctx context.Context, count int) (int64, error) {
	ctx = zlog.ContextWithValues(ctx, "component", "datastore/sqlite/GC")

	// obtain update operations which need deletin'
	ops, totalOps, err := eligibleUpdateOpts(ctx, ms.conn, count)
	if err != nil {
		return 0, err
	}

	deletedOps, err := ms.DeleteUpdateOperations(ctx, ops...)
	if err != nil {
		zlog.Error(ctx).Err(err).Msg("DeleteUpdateOperations")
		return totalOps - deletedOps, err
	}

	// get all updaters we know about.
	updaters, err := distinctUpdaters(ctx, ms.conn)
	if err != nil {
		return totalOps - deletedOps, err
	}

	for kind, us := range updaters {
		var cleanup cleanupFunc
		switch kind {
		case driver.VulnerabilityKind:
			cleanup = vulnCleanup
		case driver.EnrichmentKind:
			cleanup = enrichmentCleanup
		default:
			zlog.Error(ctx).Str("kind", string(kind)).Msg("unknown updater kind; skipping cleanup")
			continue
		}
		for _, u := range us {
			err := cleanup(ctx, ms.conn, u)
			if err != nil {
				return totalOps - deletedOps, err
			}
		}
	}

	return totalOps - deletedOps, nil
}

// distinctUpdaters returns all updaters which have registered an update
// operation.
func distinctUpdaters(ctx context.Context, conn *sql.DB) (map[driver.UpdateKind][]string, error) {
	const (
		// will always contain at least two update operations
		selectUpdaters = `SELECT DISTINCT(updater), kind FROM update_operation;`
	)
	rows, err := conn.QueryContext(ctx, selectUpdaters)
	if err != nil {
		return nil, fmt.Errorf("error selecting distinct updaters: %v", err)
	}
	defer rows.Close()

	updaters := make(map[driver.UpdateKind][]string)
	for rows.Next() {
		var (
			updater string
			kind    driver.UpdateKind
		)
		err := rows.Scan(&updater, &kind)
		switch err {
		case nil:
			// hop out
		default:
			return nil, fmt.Errorf("error scanning updater: %v", err)
		}
		updaters[kind] = append(updaters[kind], updater)
	}
	if rows.Err() != nil {
		return nil, rows.Err()
	}

	return updaters, nil
}

// eligibleUpdateOpts returns a list of update operation refs which exceed the specified
// keep value.
func eligibleUpdateOpts(ctx context.Context, conn *sql.DB, keep int) ([]uuid.UUID, int64, error) {
	const (
		// this query will return rows of UUID arrays.
		updateOps = `SELECT updater, json_group_array(ref ORDER BY date desc) FROM update_operation GROUP BY updater;`
	)

	// gather any update operations exceeding our keep value.
	// keep+1 is used because PG's array slicing is inclusive,
	// we want to grab all items once after our keep value.
	m := []uuid.UUID{}

	rows, err := conn.QueryContext(ctx, updateOps)
	switch err {
	case nil:
	default:
		return nil, 0, fmt.Errorf("error querying for update operations: %v", err)
	}

	defer rows.Close()
	for rows.Next() {
		var uuids_json string
		var updater string
		err := rows.Scan(&updater, &uuids_json)
		if err != nil {
			return nil, 0, fmt.Errorf("error scanning update operations: %w", err)
		}
		var uuids []uuid.UUID
		json.Unmarshal([]byte(uuids_json), &uuids)
		cut_off := min(len(uuids), keep)
		m = append(m, uuids[cut_off:]...)
	}
	if rows.Err() != nil {
		return nil, 0, rows.Err()
	}

	return m, int64(len(m)), nil
}

type cleanupFunc func(context.Context, *sql.DB, string) error

func vulnCleanup(ctx context.Context, conn *sql.DB, updater string) error {
	const (
		deleteOrphanedVulns = `
		DELETE FROM vuln
			WHERE id IN (
    	SELECT v2.id
     	FROM vuln v2
      	LEFT JOIN uo_vuln uvl
        	ON v2.id = uvl.vuln
        WHERE uvl.vuln IS NULL
        AND v2.updater = $1
    );
`
	)

	ctx = zlog.ContextWithValues(ctx, "updater", updater)
	zlog.Debug(ctx).
		Msg("starting vuln clean up")
	res, err := conn.ExecContext(ctx, deleteOrphanedVulns, updater)
	if err != nil {
		return fmt.Errorf("failed while exec'ing vuln delete: %w", err)
	}
	rows, err := res.RowsAffected()
	if err != nil {
		return fmt.Errorf("failed while exec'ing vuln delete (affected): %w", err)
	}
	zlog.Debug(ctx).Int64("rows affected", rows).Msg("vulns deleted")

	return nil
}

func enrichmentCleanup(ctx context.Context, conn *sql.DB, updater string) error {
	const (
		deleteOrphanedEnrichments = `
		DELETE FROM enrichment
			WHERE id IN (
    	SELECT e2.id
     	FROM enrichment e2
      	LEFT JOIN uo_enrich uen
        	ON e2.id = uen.enrich
        WHERE uen.enrich IS NULL
        AND e2.updater = $1
    );
`
	)

	ctx = zlog.ContextWithValues(ctx, "updater", updater)
	zlog.Debug(ctx).
		Msg("starting enrichment clean up")
	res, err := conn.ExecContext(ctx, deleteOrphanedEnrichments, updater)
	if err != nil {
		return fmt.Errorf("failed while exec'ing enrichment delete: %w", err)
	}
	rows, err := res.RowsAffected()
	if err != nil {
		return fmt.Errorf("failed while exec'ing enrichment delete (affected): %w", err)
	}
	zlog.Debug(ctx).Int64("rows affected", rows).Msg("enrichments deleted")

	return nil
}
