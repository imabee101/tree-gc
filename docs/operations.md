# Operating tree-gc

## Review and apply a saved plan

```sh
tree-gc plan --all --save plan.json
tree-gc apply --plan plan.json --yes
```

Apply requires enforcement and checks each candidate against the current configuration and filesystem. A branch that moved after the plan was saved is skipped. Plans generated with a simulated clock are for review only.

Use `tree-gc journal` to find a quarantine or archive ID. `tree-gc restore <id>` also accepts an unambiguous ID suffix. Restore refuses to overwrite an occupied destination. Normal expiry uses `quarantine_days`. Enforced timer runs purge expired entries, or you can request this explicitly with `tree-gc purge --yes`.

## Disk pressure

`tree-gc pressure` shows free space, pressure levels and fill-rate predictions. The guard records observations and checks for relief. In shadow mode it reports pressure and leaves cleanup candidates alone.

With the example config, soft pressure starts below 20% free or when the recent fill rate predicts crossing that threshold within 24 hours. Hard pressure starts below 10% free, with an additional size-based threshold on larger disks. The target is 25% free.

Soft relief considers old Docker build cache and recognized build output. Hard relief can also run an installed `cargo sweep` on active Cargo targets, purge quarantine early, and prune unused Docker images. Docker actions require Docker in `enforce_kinds`. Early quarantine purge is controlled separately by `pressure.purge_quarantine_early` and can affect earlier runs’ entries even if you later narrow `enforce_kinds`.

The guard measures available space during relief. Snapshots can retain deleted blocks. If enough data has been removed with little gain, the guard pauses further relief. `max_gib_per_relief` limits further work once the reported amount reaches its threshold. An individual action can exceed it.

## Inspect a scheduled run

```sh
systemctl --user list-timers 'tree-gc*'
journalctl --user -u tree-gc -u tree-gc-guard
tree-gc log --level warn
tree-gc log --since-hours 24
```

The default state directory is `~/.local/state/tree-gc`. It holds structured logs, plan history from scheduled runs, the activity clock and the action journal. Exit code 0 indicates success, 1 a command error, 2 failed actions and 3 continuing critical disk pressure.

To stop future timer activations:

```sh
systemctl --user disable --now tree-gc.timer tree-gc-guard.timer
```

## Limits worth knowing

- Process checks depend on what the current user can see through Linux procfs. For directories shared with containers, other users or other mount namespaces, use a keep marker or `protect_paths`.
- Offline or encrypted storage can look like a missing checkout. Configure `removable_prefixes` for storage whose disappearance tree-gc cannot detect.
- Remote tracking refs reflect the last fetch. Reflog-only history has a configurable protection period. Repositories using reftable do not get a copy of the archived branch’s reflog.
- Activity tracking depends on observable files such as shell or agent histories. Adjust `user_activity_files` if your workflow rarely updates those files.
- The supplied scratch rules disable transcript cleanup. Docker cleanup leaves volumes in place, but a stopped container can hold unique data in its writable layer even if that layer is small.

[Configuration and defaults](../packaging/config.example.toml) · [Back to the README](../README.md)
