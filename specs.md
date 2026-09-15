# Desktop Security Center — Development Specification

**App name**: Desktop Security Center (GApplication id: `it.antoniopicone.DesktopSecurityCenter`)
**Architectural pattern**: same approach validated for `screensaver-settings-app/` (GTK4/libadwaita, Python, a standalone Settings-style app — not a panel injected into gnome-control-center, which upstream has explicitly excluded forever).

> **Timeline constraint, to keep in mind for every decision in this document**: today is September 15, the demo is September 17. This document describes the full vision (9 categories), but the "Roadmap to September 17" section at the bottom is what actually matters right now — everything else is backlog the app must be able to absorb in the future without a refactor, not work to complete today.

---

## 1. Goal

A single app that aggregates desktop/laptop/workstation security signals otherwise scattered across terminal commands, config files, and separate panels — with **unprivileged reads whenever possible** and **explicit privileged actions via `pkexec`**, never handling credentials directly (the same rule already in force for the other scripts in the recipe).

It does not replace Ubuntu Pro / the native Security Center (reference screenshot): it complements it for the aspects that tool doesn't cover at all (local firewall, remote-access services, Wi-Fi, backup, application surface).

---

## 2. Application architecture

Mirrors 1:1 the choices already validated for the Screensaver app:

- **`Adw.NavigationSplitView`**: sidebar with the list of modules (categories); content = state + actions of the selected module.
- **Registry pattern** (`registry.py`): each category is a self-describing Python module (title, icon, check function, action function, whether it requires privileges). Adding a category = adding one entry to the registry, without touching the rest of the app — the same extensibility already used for Ken Burns/future screensavers.
- **No continuously-polling daemon for the MVP**: each module refreshes on demand (a "Refresh" button or opening the module), not via a permanent timer — this avoids introducing a new systemd service that would need to be validated in a hurry before September 17. A future continuous-monitoring daemon (for proactive notifications like "new port opened") is explicit backlog, not MVP.
- **Read vs. action**:
  - *Read* (firewall state, listening ports, etc.): always as a normal user, via `Gio.Subprocess` async (never block the UI) — the same pattern already used for "Refresh now" in the screensaver app.
  - *Privileged action* (enabling ufw, closing a port, disabling a service): a single helper binary launched via `pkexec`, never interactive `sudo` inside the app. Every privileged action shows a textual diff of what is about to change before executing (consistent with "never handle credentials directly" and with the established habit of being explicit about system changes).
- **No new heavy dependencies**: prefer parsing `/proc`, `/sys`, and commands already present on the system (`ss`, `nmcli`/`iwd`, `systemctl`, `ufw`/`nft`) over additional Python libraries — consistent with the "only compile/install if truly necessary" approach already followed for Howdy/Planify.

### Proposed structure

```
desktop-security-center/
├── src/
│   ├── app.py                  # GApplication + main window (NavigationSplitView)
│   ├── registry.py             # module list, like the screensaver's registry.py
│   ├── modules/
│   │   ├── firewall.py
│   │   ├── remote_access.py
│   │   ├── network_wifi.py
│   │   ├── auth_accounts.py
│   │   ├── updates.py
│   │   ├── backup.py
│   │   ├── hardware_peripherals.py
│   │   ├── app_permissions.py
│   │   └── privacy.py
│   └── security_score.py       # aggregate score calculation (backlog, see §5)
├── helpers/
│   └── desktop-security-center-helper  # root binary/script, the single pkexec entry point
├── schemas/
│   └── it.antoniopicone.DesktopSecurityCenter.gschema.xml   # app preferences (thresholds, enabled modules)
└── 28-desktop-security-center-setup.sh # setup script, same pattern as 23-kenburns-screensaver-setup.sh
```

---

## 3. Modules — per-category specification

For each module: **what to show**, **how to read it technically**, **required permissions**, **available actions**, **priority** (P0 = MVP demo, P1 = right after, P2 = true backlog).

### 3.1 Firewall — **P0**

- **Confirmed by Antonio**: ufw is already present on the image (a standard Ubuntu package, not to be installed by `28-desktop-security-center-setup.sh`), but **inactive by default** — this is exactly the "installed but off" scenario this module must detect and let the user fix with one click, the most direct use case for the demo.
- **State**: active/inactive (ufw as the preferred front-end, with direct reading of `nft list ruleset` only as a diagnostic fallback if ufw turned out to be absent on a different image variant).
  - Reading: `ufw status verbose` (text parsing; reading just the enabled/disabled state should not require privileges — verify in practice whether the "verbose" level of detail with the rule list instead requires `sudo`; if so, still show enabled/disabled without privileges and load the detailed rules only on explicit user request, via the helper).
- **Listening ports**: `ss -tlnp` / `ss -ulnp` (getting the process name for some ports requires privileges — evaluate whether to accept "unknown PID" in unprivileged reads, or to request the privileged helper only for this view).
  - Enrichment: map PID → readable application name (`/proc/<pid>/comm`) and, where possible, an icon/friendly name (e.g. `sshd` → "SSH remote access").
  - Visually highlight: ports listening on `0.0.0.0`/`::` (all interfaces) vs. `127.0.0.1` only (local, lower risk).
- **Actions (confirmed in scope for the September 17 MVP)**:
  - **"Enable ufw"**: `ufw enable` via the `pkexec` helper, with a before/after summary (default rules `deny incoming` / `allow outgoing`) shown before executing — this is the flagship demo action, it must be reliable and tested multiple times before September 17.
  - Disable ufw, add/remove a rule for a port (via the root helper) — P1, not necessary for the first demo but should already be left in the registry as disabled/"coming soon" actions if not ready in time.
- **Design note**: ufw is already the Ubuntu standard and is what a Canonical principal engineer will expect to see handled well — high priority for the demo too.

### 3.2 Remote access / control services — **P0**

- **SSH**: `systemctl is-active ssh.service` (or `sshd`), then parse `/etc/ssh/sshd_config` (+ `sshd_config.d/*`) for `PasswordAuthentication`, `PermitRootLogin`, `Port`. Highlight in red: password auth enabled + exposed on all interfaces.
- **GNOME remote desktop** (`gnome-remote-desktop`, integrated RDP/VNC): state via `org.gnome.Mutter.RemoteDesktop`/gsettings `org.gnome.desktop.remote-desktop` (schema to be verified against the real GNOME 50 version before hard-coding it).
- **Third-party tools** (TeamViewer, AnyDesk, RustDesk, x11vnc, xrdp): detection via known systemd unit/process — a whitelist to maintain, not generic discovery.
- **Actions**: stop/disable the service, open guided SSH config editing (Port field, password-auth toggle) via the helper.

### 3.3 Wi-Fi and local network — **P0**

- **NetworkManager confirmed, not iwd**: this is an **Ubuntu Desktop** install (GNOME, GDM, `source: id: ubuntu-desktop-minimal` in `autoinstall.yaml.tpl`), not Ubuntu Server/minimal netplan — on Ubuntu Desktop the standard network manager is always NetworkManager, with `nmcli` as the correct front-end. iwd is relevant as an *optional internal Wi-Fi backend* that NetworkManager can use instead of wpa_supplicant, but it doesn't change which tool this module should use: `nmcli` works identically in both cases because it talks to NetworkManager, not directly to the underlying backend. No ambiguity to resolve at runtime — `nmcli` is hard-coded directly.
  - Minimal robustness still recommended: if `nmcli` is not on the PATH or `NetworkManager.service` is not active, the module shows a "NetworkManager unavailable" banner instead of failing silently — not a real fallback to iwd (out of scope, not an expected scenario on this image).
- **Current network**: SSID, security type (Open/WEP/WPA2/WPA3) via `nmcli -t -f active,ssid,security dev wifi`.
- **Saved networks with weak security**: iterate NetworkManager profiles (`nmcli -t -f name,type connection show`) and flag those on WEP or open.
- **Bluetooth**: `bluetoothctl show` for discoverable/pairable when active and not needed.
- **Actions**: disconnect from an open network with a warning, disable Bluetooth discoverability, delete a saved weak Wi-Fi profile.

### 3.4 Authentication and local access — **P1**

- **User accounts**: parse `/etc/passwd` + `getent group sudo`, highlight accounts with a login shell and no password (`passwd -S` per user, requires privileges).
- **Recent failed logins**: `journalctl -u ssh.service -p warning` or a targeted read via `journalctl _COMM=sshd` filtering for "Failed password" patterns.
- **Howdy**: enrollment state (`howdy list`), confirmation that the password fallback always remains available (reading the pam-configs fragment generated by the recipe).
- **Screen lock**: `org.gnome.desktop.session idle-delay` + `org.gnome.desktop.screensaver lock-enabled` (the same schemas already read by the Screensaver app — possible code reuse between the two apps).

### 3.5 Updates and vulnerabilities — **P1**

- **Pending updates**: `apt list --upgradable` (or reading the apt cache directly without invoking `apt update` from inside the app, to avoid side effects from a simple status refresh).
- **unattended-upgrades**: enablement state (`systemctl is-enabled unattended-upgrades.timer`), last run (log under `/var/log/unattended-upgrades/`).
- **Kernel Livepatch / Ubuntu Pro ESM**: if Ubuntu Pro is attached, read `pro status --format json` (the official command, structured output) instead of fragile text parsing.
- **fwupd**: `fwupdmgr get-updates` for available firmware.
- **Actions**: trigger a manual `unattended-upgrade`, open Software Updater for the guided upgrade (don't reinvent the apt flow inside this app).

### 3.6 Backup — **P2 (depends on work not yet done)**

> Explicitly flagged by Antonio as a prerequisite: **the incremental cloud backup process doesn't exist yet** — this module of the app is just the *dashboard* for a state that today has nothing producing it. The backup script itself must be designed/implemented first (likely candidate: `restic`/`rclone` to the user's already-configured cloud, with retention and client-side encryption — to be decided in a dedicated session, out of scope for this document).
- **Once it exists**, the module will show: present/absent, destination, last successful run, size, whether encrypted.
- **Snapper snapshots** (local, already implemented) can serve as a minimal placeholder for September 17: "local backup via Snapper snapshot: yes, root+home, last snapshot <timestamp>" — not a real offsite backup, but immediately verifiable and honest about its limitation.

### 3.7 Hardware and peripherals — **P1**

- **USBGuard** (already implemented): number of authorized/blocked devices, recent events (`usbguard list-devices`, daemon log).
- **Secure Boot**: state (`mokutil --sb-state` or reading the EFI variable) — shown as a deliberate choice made by the recipe (Limine unsigned), not just a red light with no context, consistent with what's already documented for Howdy/Secure Boot in the test VM.
- **TPM**: presence/version (`tpm2_getcap` if available), PCRs used by the binding (0+4, already known from the recipe).
- **Webcam/microphone in use**: an "in use by process X right now" indicator — needs investigating which mechanism GNOME 50 exposes (PipeWire has node introspection; verify whether a stable D-Bus API exists before committing to it, otherwise backlog).

### 3.8 Apps, permissions, and software surface — **P2**

- **Flatpak permissions**: `flatpak info --show-permissions <app>` for every installed app, highlighting unnecessary `filesystem=home` or `socket=x11` (Flatseal-style, but read-only + a link to Flatseal for fine-grained management, to avoid duplicating a tool that already exists and is mature).
- **Snap confinement**: `snap connections` to see granted interfaces.
- **systemd services listening on the network that aren't essential**: cross-reference with the Firewall module (§3.1) more than a standalone module.
- **Autostart**: enumerate `~/.config/autostart/*.desktop`, including `NoDisplay=true` entries — exactly the kind the recipe itself installs for Howdy/wsf — also useful to verify that the user can see what the recipe has set up for them.

### 3.9 Privacy — **P2**

- Telemetry (`ubuntu-report`), location services (`org.gnome.system.location enabled`), recent-files history (`org.gnome.desktop.privacy remember-recent-files`).
- Custom CA certificates installed (`/usr/local/share/ca-certificates/`, `trust list` with `p11-kit`) — flag the presence of non-standard CAs without passing automatic judgment (they could be legitimate, e.g. a corporate VPN).

---

## 4. UI/UX

- Sidebar (`Adw.NavigationSplitView`, same pattern as the Screensaver app): an icon + a synthetic status per row (green/yellow/red dot), not free text — readable at a glance.
- Module content: `Adw.PreferencesGroup` with `Adw.ActionRow`/`Adw.SwitchRow` per entry, a "Refresh" button at the top for explicit refresh (no automatic polling in the MVP, see §2).
- Error banner per module if an underlying command is missing (e.g. `ufw` not installed) — the same banner pattern already used in the Screensaver app for missing components, with a guided-setup button where it makes sense.
- **Aggregate score (Security Score)**: deferred to after the MVP — it risks being an arbitrary number with weights not discussed with Antonio; better to introduce it once the real modules exist and it can be calibrated against reality.

---

## 5. Security of the app itself

- No credentials managed/stored by the app (consistent with the recipe's general rule).
- A single privileged helper (`security-center-helper`), invoked only via `pkexec`, with a fixed and verified set of subcommands (never `eval` of free-form input) — the same principle already used for `pkexec` in "Run initial setup" in the Screensaver app.
- Every action that changes system state (firewall, services, SSH config) shows a before/after summary before executing.

---

## 6. Integration with the recipe

- Standalone script `scripts/28-security-center-setup.sh`, same pattern as `23-kenburns-screensaver-setup.sh`: installs dependencies (`ufw` if not already present — to verify, it might already be there by default on Ubuntu Desktop), copies the app to `~/.local/share/security-center`, installs the gsettings schema, and a `.desktop` entry.
- **Not integrated into `disk-setup/autoinstall.yaml.tpl` for September 17** — the same cautious choice already made for the Screensaver app (standalone script first, integration into the late-commands only after verification on real hardware).

---

## 7. Roadmap to September 17 — the part that matters right now

With two days available, realistically:

1. **App scaffolding** (half a day): `app.py` + `registry.py` copied/adapted from `screensaver-settings-app/`, sidebar with all 9 categories visible but only some "alive".
2. **Real, working P0 modules**: Firewall (§3.1) — **including the "Enable ufw" button with a real `pkexec` helper, the flagship demo action** —, Remote-access services (§3.2), Wi-Fi (§3.3) — these are the ones with standard commands, simple unprivileged reads, and the greatest "demo effect" (they're exactly the examples given at the start). The `pkexec` helper for ufw needs to be tested multiple times before September 17 (enable from an off state, state refresh after the action, behavior if the user cancels the authentication prompt).
3. **One P1 module if time allows**: Updates (§3.5) is probably the quickest to add after the P0s (apt/pro status commands already well documented).
4. **Everything else (Backup, Hardware, App permissions, Privacy, Authentication)**: present in the UI as an entry but with an "in development" banner — showing the full vision without having to pretend it's already implemented, consistent with how the "not yet verified on real hardware" state was honestly handled for the recipe's other components.
5. **Tested only in a sandbox with Xvfb for rendering**, like the Screensaver app — none of the privileged actions should be tested against the real system without Antonio's direct supervision, for the same reason the recipe's other "not yet tested" scripts are explicitly flagged as such.

---

## 8. Open questions for Antonio

The four questions from the previous version are resolved (NetworkManager confirmed, ufw present but inactive, the ufw-enable action in scope for the MVP, app name "Desktop Security Center" / `it.antoniopicone.DesktopSecurityCenter`). No blocking question remains to start scaffolding — the only decisions still open are implementation details (e.g. whether `ufw status verbose` requires privileges even for just reading enabled/disabled — to verify in practice, not in the abstract) and none of them block starting the work.
