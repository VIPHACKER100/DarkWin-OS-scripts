# DOCUMENTATION — DarkWin Security Suite

**Overview**
- **Purpose**: Provide automation, configuration, and resources to build a Windows security research environment and run common pentest workflows.
- **Audience**: Operators, security researchers, and maintainers who run or extend the automation scripts.

**Prerequisites**
- Windows 10 (host or VM) with administrative privileges.
- PowerShell 5.1 or later.
- Internet access to download tools and updates.
- Recommended: 20GB free disk space.

**Execution policy (one-time, per session)**
Run PowerShell as Administrator or use a process-level policy to allow script execution:

```powershell
Set-ExecutionPolicy -ExecutionPolicy RemoteSigned -Scope Process
```

**Quick Start**
1. Open PowerShell in the project root (where `setup.ps1` lives).
2. Set execution policy (see above).
3. Run the setup script:

```powershell
.\setup.ps1
```

4. After setup, run a security scan (example):

```powershell
.\security_scan.ps1
```

**Scripts (top-level)**
- `setup.ps1`: Installs and configures the core environment and optional tools.
  - Usage: `.\setup.ps1`
- `security_scan.ps1`: Orchestrates multiple scanning tools (nmap, openvas, etc.).
  - Usage: `.\security_scan.ps1 -ScanProfile Full`
- `update_tools.ps1`: Fetches and updates tool packages and definitions.
  - Usage: `.\update_tools.ps1`
- `install_additional_tools.ps1`: Installs optional utilities listed in `TOOLS.md`.
  - Usage: `.\install_additional_tools.ps1`
- `generate_branding.ps1`: Applies brand assets from `DarkWin-Resources/`.

For per-script help, run:

```powershell
.\scriptname.ps1 -?    # Replace scriptname.ps1 with the script file
```

**Configuration files**
- `tools_config.json`: Controls which tools and packages are installed.
- `burp_config.json`: Configuration used by Burp automation scripts.
- `darkwin_config.json`: General project-level options and toggles.
- `msf.conf`, `nmap.conf`, `wireshark.conf`: Per-tool config templates.

Modify these JSON files to customize behavior before running `setup.ps1` or other automation.

**Folder layout (not exhaustive)**
- `DarkWin-Resources/Branding/`: Icons, logos, wallpapers.
- `DarkWin-Resources/Scripts/`: Helper scripts and modules.
- `*.ps1`: Main automation scripts in the repository root.
- `*.md`: Guides and automation documentation.

**Common Workflows**
- Install everything (fresh environment):

```powershell
Set-ExecutionPolicy -ExecutionPolicy RemoteSigned -Scope Process; .\setup.ps1
```

- Update tools and definitions:

```powershell
.\update_tools.ps1
```

- Run a focused network scan:

```powershell
.\security_scan.ps1 -ScanProfile Network
```

**Troubleshooting**
- PowerShell denies script execution: set process execution policy as shown above.
- Network downloads fail: ensure proxy or firewall rules permit the script's outbound connections.
- A specific tool install fails: inspect `setup.log` (if present) or re-run the tool's installer manually.

**Contributing**
- Fork the repo, make small focused changes, and open a PR explaining the intent.
- Add or update documentation alongside code changes.

**Contact & Support**
- For feature requests or issues, open an issue in the project's issue tracker or contact the repository owner.

**License**
- See `LICENSE` in the repository root.

---

If you'd like, I can:
- Add per-script argument documentation and examples.
- Generate a one-page quick-start `QUICKSTART.md` with screenshots or step-by-step images.

