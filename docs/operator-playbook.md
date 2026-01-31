# Operator Playbook (triage → why → reproduce)

This playbook is a pragmatic guide for keeping wa healthy during day-to-day use.
It focuses on fast diagnosis, safe remediation, and actionable artifacts.

## Quick start

```bash
wa triage
wa triage -f json
```

If something needs attention, follow the relevant flow below.

---

## Flow 1: triage → why → fix

Use this for unhandled events or workflows that need intervention.

1) Triage to find the affected pane/event:

```bash
wa triage --severity warning
wa events --unhandled --pane <pane_id>
```

2) Explain the detection:

```bash
wa why --recent --pane <pane_id>
# optional deep dive on a specific decision
wa why --recent --pane <pane_id> --decision-id <id>
```

3) Fix with an explicit action (examples):

```bash
# handle compaction event
wa workflow run handle_compaction --pane <pane_id>

# check a workflow that looks stuck
wa workflow status <execution_id>
```

Tip: If you are unsure, run workflows with `--dry-run` first.

---

## Flow 2: triage → reproduce → file issue

Use this for crashes or persistent failures you can’t fix locally.

1) Export the latest crash bundle:

```bash
wa reproduce --kind crash
```

2) Collect a diagnostics bundle (optional but recommended):

```bash
wa diag bundle --output /tmp/wa-diag
```

3) File an issue with:
- crash bundle path
- triage output (plain or JSON)
- any recent wa logs

---

## Flow 3: triage → mute / noise control

If an event is noisy but safe, reduce noise without losing observability.

### TUI mute (fastest)

In the TUI triage view:
- Select the event
- Press `m` to mark it handled (muted)

### Disable specific rules (config)

You can silence a specific detection rule via pack overrides:

```toml
# ~/.config/wa/wa.toml
[patterns.pack_overrides.core]
disabled_rules = ["core.codex:usage_reached"]
```

Apply changes and reload if needed:

```bash
wa config validate
wa config reload
```

Note: Disabling rules prevents those detections from firing entirely.

---

## Common commands (copy/paste)

```bash
# triage and deep-dive
wa triage
wa triage --severity error
wa why --recent --pane <pane_id>

# event and workflow inspection
wa events --unhandled --pane <pane_id>
wa workflow status <execution_id>

# crash + diagnostics
wa reproduce --kind crash
wa diag bundle --output /tmp/wa-diag
```

