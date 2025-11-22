# DarkWin — Security & Pentest Automation for Windows

Concise collection of automation scripts, configs, and resources to build and manage a Windows-based security research environment (DarkWin).

**Where to start**: read the full documentation in `DOCUMENTATION.md` (this file is an executive summary).

**Quick actions**:
- **Install prerequisites and configure system**: run `.\setup.ps1` from a PowerShell prompt (see `DOCUMENTATION.md` for execution policy notes).
- **Run a security scan**: run `.\security_scan.ps1`.
- **Update tools**: run `.\update_tools.ps1`.

**Important files**:
- `setup.ps1`: main setup and installer script.
- `security_scan.ps1`: orchestrates multiple scanning tools.
- `update_tools.ps1`: updates installed toolset.
- `tools_config.json`, `burp_config.json`, `darkwin_config.json`: JSON configs used by scripts.

**Project structure (top-level)**:
- `*.ps1` — PowerShell automation scripts (setup, scans, integrations).
- `*.md` — guides and automation docs (this project contains several automation guides).
- `DarkWin-Resources/` — branding, scripts, and resource files used by the build.

If you need more detailed developer or operator instructions, open `DOCUMENTATION.md`.

---

If you'd like, I can also:
- Add per-script usage examples to `DOCUMENTATION.md`.
- Generate an operations checklist or a shorter quick-start one-pager.