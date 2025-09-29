# CVE Tool

A [Claircore](https://github.com/quay/claircore)-based CVE manager (see also [clair-action](https://github.com/quay/clair-action/)).

# Build

Install Go development tools and libraries (`goland`) and GNU `make`.
Run 
```
$ make build
```
to build the CLI tool.

# Run

## Update (or Initialize) the Database

In order to use the tool for CVE analysis and report generation first the CVE database must be initialized 
and filled with CVE records.

Run
```
$ ./cvetool update --db-path=./matcher.db
```
to create (or update) the DB (SQLite).

The `--db-path` argument is the path to the database location. If the parameter is ommited the tool
creates ephemeral (in-memory) database.

The initial update procedure could take up to 30 minutes. Further updates will be significantly faster.

## Scan and Generate Report

Run
```
$ ./cvetool report --root-path=/usr --db-path=./matcher.db
```
to scan the system and generate vulnerabilities report.

The `--root-path` argument defines root directory of the target file system. Currently the tool 
fails if there is a problem with accessing files (https://github.com/ComplianceAsCode/cvetool/issues/9).
Therefore for local system it is recommended to set the argument to `/usr` and run the tool as root user (sudo).

Default report format is `clair` (JSON). It could be changed with the `--format` argument.

Run the tool with `--help` argument for more information.
