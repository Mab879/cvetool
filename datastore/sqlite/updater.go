package sqlite

import (
	"context"
	"fmt"
	"time"

	"github.com/quay/claircore/libvuln/driver"
	"github.com/quay/zlog"
)

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

	ctx = zlog.ContextWithValues(ctx, "component", "internal/vulnstore/sqlite/recordUpdaterSetStatus")

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
