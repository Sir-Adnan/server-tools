# Rollback — manifest design and guarantees

## The problem with v1

Legacy rollback restored from a `latest` symlink over a hardcoded file list.
Running optimize twice made "latest" a backup of *already-modified* files, so
rollback could never reach the original server state; several files (e.g.
`resolv.conf` on non-resolved systems, `modules-load.d/bbr.conf`) were never
rolled back at all; and `/swapfile` was deleted even when the provider had
created it. v2 fixes this structurally.

## Design

Every change goes through `st_track_file PATH` **before** the file is touched
(CLAUDE.md rule 3). That produces:

1. **Pristine copy** — `backups/original/<abs-path>`, written only the first
   time ServerTools ever touches that path, never overwritten. This is the
   "factory state" of the server as we found it.
2. **Per-run copy** — `backups/runs/<run-id>/<abs-path>`, the file as it was
   at the start of this run.
3. **Manifest row** — appended to `manifest.tsv`:

```tsv
# timestamp	run_id	action	target
2026-07-19 20:14:03	20260719-201401	modified	/etc/sysctl.d/99-server-tools.conf
2026-07-19 20:14:03	20260719-201401	created	/etc/modules-load.d/server-tools.conf
```

`action` is `modified` (file existed → backed up) or `created` (file did not
exist → rollback deletes it). A file that never existed before the tool ran
can therefore never be "restored" into existence, and a pre-existing file
(like a provider's `/swapfile`) is never deleted by rollback.

## Rollback algorithm (`rollback_latest`)

1. Find the newest `run_id` in the manifest.
2. Replay that run's rows **in reverse order**:
   - `modified` → copy back from `runs/<run-id>/<abs-path>`;
   - `created` → remove the target.
3. Report restored/removed/missing counts honestly.

## Guarantees and limits

- **Guaranteed:** file contents return to their state at the start of the
  rolled-back run; first-touch originals are always available for a future
  "restore to factory state" feature.
- **Not automatic:** runtime state — already-loaded sysctl values, running
  services, active swap. The UI says so explicitly and recommends a reboot
  for a guaranteed clean slate. (Phase 2 adds targeted re-apply steps such as
  `sysctl --system` after restoring sysctl files.)
