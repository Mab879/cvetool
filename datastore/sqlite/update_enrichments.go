package sqlite

import (
	"context"
	"crypto/md5"
	"database/sql"
	"fmt"
	"io"
	"sort"
	"strings"

	"github.com/google/uuid"
	"github.com/quay/claircore/datastore"
	"github.com/quay/claircore/libvuln/driver"
	"github.com/quay/zlog"
)

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
