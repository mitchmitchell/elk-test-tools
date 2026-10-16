# elk-test-tools

Private test tooling for the Elk E27 **TEST** panel. Not for production panels.

Tools land through pull requests reviewed by Architect. See each tool's section
below once merged.

## elk-remove-test-link (decision 32)

Removes specific links from the **TEST** panel only. Dry-run by default.

```
elk-remove-test-link --protect 119112725266 \
    --remove 246915998877 --expect-name "Old Link A"                            # dry run
ELK_TEST_INSTALLER_CODE=... elk-remove-test-link --protect 119112725266 \
    --remove 246915998877 --expect-name "Old Link A" \
    --apply --log-file link-removal-log.md                                      # delete
```

Guardrails (hard-coded, not overridable):
- Refuses unless the panel MAC is `cc031eb03b20`, and every `--remove` serial has the
  matching Network Devices name in `--expect-name`.
- Connects over the tool's **own dedicated link**, never the TEST HA entry's link.
- `--protect SERIAL` (12 hex, repeatable) is **required**: every run, dry-run included,
  refuses without at least one. No serials are built in (Mitch, Oct 16 2026). The tool's
  own link is always protected. Hitting a protected link aborts the whole run. A
  protected link already absent before the run is not required to appear afterwards.
- **Touch screens are never removed**, blocked by device type rather than serial. The
  type is the `mn` (model number) from `net_dev.get_list`. Only `mn` 222 (elke27/HA
  integration links) is removable. `mn` 100 (touch screen/tablet in the Dealer API
  examples), any other value, or a missing value is protected and shown as
  `PROTECT [touch screen]` in the dry-run table.
- No remove-all, no wildcards, max 6 exact 12-hex serials; `net_dev.default` is never sent.
- `--apply` also needs all areas disarmed and the TEST MAC typed at a prompt.
- Installer code: only from `ELK_TEST_INSTALLER_CODE`, read only on `--apply`, removed from
  the environment, sent in one authenticate frame, never logged/printed/stored (tested).
  There is no `--pin` flag.
- After deletes it re-reads the inventory and reports each revoked link's session state.

**Status:** the live transport is not wired yet. It moves onto the elke27 raw API
pass-through (decision 34); until then only the fake-panel tests run.

Dev: `pip install -e ".[dev]" && ruff check . && pytest`

## Live transport (draft, decision 34/38)

`elk_test_tools.elke27_transport.Elke27Transport` sends every message through
elke27's raw pass-through (`Elke27Client(enable_raw_passthrough=True)` and
`async_raw_request(..., allow_installer=True)`). The installer code goes only
through elke27's `control_authenticate`. The tool's own link is read from the
JSON file named by `ELK_TEST_LINK_FILE` (`host`, `port`, `own_link_sn`,
`link_keys`). The file must be mode 0600 and outside any git repo and the vault (the tool refuses otherwise, and never logs its path or contents). Never use the HA
entry's link. Installer codes with a leading zero are refused (the panel pin is numeric). elke27 is pinned to the `feat/raw-passthrough` branch until it's
released. Not yet run against any panel.
