# Summary

<!-- What does this change and why? -->

## Checklist

- [ ] Edited `src/` only (never `dist/` by hand) and ran `./build.sh`
- [ ] `make lint` passes (ShellCheck + shfmt)
- [ ] `./tests/smoke.sh` passes
- [ ] Every created/modified system file goes through `st_track_file` first
- [ ] No new runtime dependencies; optional tools are `has_cmd`-guarded
- [ ] No daemons/cron/telemetry introduced (zero-footprint rule)
- [ ] `CHANGELOG.md` updated for user-visible changes
