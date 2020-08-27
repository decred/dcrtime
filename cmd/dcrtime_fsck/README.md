dcrtime_fsck
============

// XXX: update docs and mention postgres

The filesystem backend can under rare circumstances become incoherent. This
tool iterates over all timestamp directories and corrects known failures.

## Flags

```
  -file		Journal file. When set actions that will/would be taken are
		journaled. This flag works independently of the -fix flag.
  -fix		Attempt to correct encountered failures.
  -host		Non default block explorer host. Defaults based on -testnet
		flag.
  -printhashes	Print all hashes encountered during the run. This is very
		loud.
  -source	Non default source directory of the filesystem backend.
  -testnet	Use testnet.
  -v		Verbose
```

## Important

Note that the journal may not be identical between a dry- and real run. This
can happen as the filesystem is modified and thus can affect the result of the
journal. This is normal.

The filesystem backend uses lazy timestamp record flushes in order to keep the
source code as simple as possible. This has a result that unless a user has
requested the timestamp information for a given unflushed hash the entire flush
record does not exist. In the `dcrtime_fsck` tool that manifests as `Unflushed`
hash prints. This is normal.

## Examples

Run fsck non-verbose, use non-default filesystem source path and output
potential corrections to `journal.json`.
```
$ dcrtime_fsck -file journal.json -source ~/dcrtime/data/mainnet/
=== Root: /home/marco/dcrtime/data/mainnet/
=== FSCK started Mon Feb 18 14:41:08 CST 2019
--- Phase 1: checking timestamp directories
--- Phase 2: checking global timestamp database
--- Phase 3: checking duplicate digests
=== FSCK completed Mon Feb 18 14:42:50 CST 2019
```
