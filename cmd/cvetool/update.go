package main

import (
	"fmt"
	"net/http"
	"time"

	"github.com/ComplianceAsCode/cvetool/datastore"
	"github.com/quay/claircore/libvuln"
	_ "github.com/quay/claircore/updater/defaults"
	"github.com/urfave/cli/v2"
)

var updateCmd = &cli.Command{
	Name:    "update",
	Aliases: []string{"u"},
	Usage:   "update the database",
	Action:  update,
	Flags: []cli.Flag{
		&cli.PathFlag{
			Name:    "db-path",
			Value:   "",
			Usage:   "where to look for the matcher DB",
			EnvVars: []string{"DB_PATH"},
		},
	},
}

func update(c *cli.Context) error {
	ctx := c.Context
	dbPath := c.String("db-path")
	matcherStore, err := datastore.NewSQLiteMatcherStore(dbPath, true)
	if err != nil {
		return fmt.Errorf("error creating sqlite backend: %v", err)
	}

	cl := &http.Client{
		Timeout: 2 * time.Minute,
	}

	matcherOpts := &libvuln.Options{
		Client:                   cl,
		Store:                    matcherStore,
		Locker:                   NewLocalLockSource(),
		DisableBackgroundUpdates: true,
		UpdateRetention:          3,
		UpdateWorkers:            1,
		// We don't need matchers for update procedure
		MatcherNames: []string{},
		// Limit CVE feed and enrichment updaters to RHEL ecosystem
		UpdaterSets: []string{"rhel-vex", "clair.cvss"},
	}

	lv, err := libvuln.New(ctx, matcherOpts)
	if err != nil {
		return fmt.Errorf("error creating Libvuln: %v", err)
	}

	if err := lv.FetchUpdates(ctx); err != nil {
		return fmt.Errorf("error updating vulnerabilities: %v", err)
	}
	return nil
}
