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
to create or update the DB (SQLite).

The `--db-path` argument is the path to the database location. 

> [!IMPORTANT]
> If the parameter is omitted the tool creates ephemeral (in-memory) database, which will be discarded after the tool finishes its job.

The initial update procedure could take up to 30 minutes. Further incremental updates will be significantly faster.

## Scan Local System

Run
```
$ ./cvetool report --root-path=/ --db-path=./matcher.db
```
to scan the underlying system and generate vulnerabilities report.

The `--root-path` argument defines root directory of the target file system.

> [!CAUTION]
> Currently the tool fails if there is a problem with accessing files (https://github.com/ComplianceAsCode/cvetool/issues/9).
> **At this moment it is not possible to get a report for the local system**.

## Scan a Container Image

Run
```
$ ./cvetool report --image-path=./rhel-10-ubi.tar --db-path=./matcher.db
```
to scan a `podman/docker image save ...`-compatible `.tar` image and generate vulnerabilities report.

## Scan a Remote Container Image

Run
```
$ ./cvetool report --image-ref=registry.access.redhat.com/ubi10/ubi --db-path=./matcher.db
```
to pull and scan an image from a repository and generate vulnerabilities report.

## Scan a Virtual Machine Image

The tool does not directly support indexing VM images. But it can work with a mounted file system, e.g. with `guestmount`.

Run
```
$ mkdir -p ./rhel10-vm
$ guestmount -a ~/.local/share/gnome-boxes/images/rhel10.0 -i --ro ./rhel10-vm
$ ./cvetool report --root-path=./rhel10-vm --db-path=./matcher.db
```
to mount the file system, scan and generate vulnerabilities report.

# Report Formats

Default report format is `plain`, which represents basic information about found vulnerabilities in a human-readable form.
It could be changed with the `--format` argument. Possible options are 'clair', 'quay' and 'sarif'.

# Help

Run the tool with `--help` argument for detailed information about invocation options.
