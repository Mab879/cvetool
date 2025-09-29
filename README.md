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
to create (or update) the DB. The information is stored in SQlite format.

The `--db-path` argument is the path to the database location. If the parameter is ommited the tool
creates ephemeral (in-memory) database.

The initial update procedure could take up to 30 minutes. Further updates will be significantly faster.

## Scan and Generate Report

Run
```
$ ./cvetool -l debug report --root-path=/usr --db-path=./matcher.db
```
to scan the system and generate vulnerabilities report.

The `--root-path` argument defines the root directory of the target file system. Currently the tool 
fails if there is a problem with accessing files. For local system is recommended to start from `/usr`
and run the tool as root.

Default report format is `clair`. It could be changed with the `--format` argument.
