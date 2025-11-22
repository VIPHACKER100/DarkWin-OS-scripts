# Security Automation Guide

## Overview
This guide explains how to use the security automation script (`security_automation.ps1`) to perform various security tasks on your Windows system. The script provides a comprehensive set of tools for security monitoring, scanning, hardening, and auditing.

## Prerequisites
- Windows 10 or later
- PowerShell 5.1 or later
- Administrator privileges
- Required modules:
  - ActiveDirectory
  - NetSecurity
  - Defender
  - SecurityPolicy

## Installation
1. Copy the `security_automation.ps1` script to your system
2. Open PowerShell as Administrator
3. Navigate to the script directory
4. Run the script: `.\security_automation.ps1`

## Features

### 1. System Security Check
Checks the current security status of your system, including:
- Windows Defender status
- Firewall configuration
- Windows Update status
- BitLocker status
- UAC settings
- Critical services status

### 2. Security Scanning
Performs comprehensive security scans:
- Nmap port scanning (quick or full)
- Burp Suite vulnerability scanning
- Metasploit auxiliary scanning
- Generates detailed reports

### 3. Security Monitoring
Monitors system security in real-time:
- Windows Event Logs
- Network connections
- File system changes
- Process monitoring

### 4. Security Hardening
Applies security hardening measures:
- Disables unnecessary services
- Configures Windows Defender
- Sets up firewall rules
- Configures UAC
- Implements password policies
- Enables BitLocker

### 5. Security Audit
Performs comprehensive security audits:
- User account analysis
- Software inventory
- System configuration
- Network configuration
- Security policies

### 6. Security Reporting
Generates detailed HTML reports including:
- System security status
- Audit results
- Security recommendations

## Usage

### Running the Script
1. Open PowerShell as Administrator
2. Navigate to the script directory
3. Run: `.\security_automation.ps1`

### Menu Options
1. **Check System Security**
   - Displays current security status
   - No parameters required

2. **Start Security Scan**
   - Requires target IP/hostname
   - Optional scan type (quick/full)
   - Example: `2` then enter target and scan type

3. **Start Security Monitoring**
   - Begins real-time monitoring
   - No parameters required

4. **Start Security Hardening**
   - Applies security hardening measures
   - No parameters required

5. **Start Security Audit**
   - Performs comprehensive audit
   - No parameters required

6. **Generate Security Report**
   - Creates HTML report
   - No parameters required

7. **Exit**
   - Closes the script

## Output Files
- Scan results: `C:\SecurityTools\Scans\<timestamp>\`
- Reports: `C:\SecurityTools\Reports\security_report_<timestamp>.html`
- Logs: `C:\SecurityTools\Logs\`

## Best Practices
1. Run the script with Administrator privileges
2. Perform regular security checks
3. Review and act on security recommendations
4. Keep the script and its dependencies updated
5. Back up important data before security hardening

## Troubleshooting

### Common Issues
1. **Module Not Found**
   - Solution: Install required PowerShell modules
   - Command: `Install-Module <module-name>`

2. **Access Denied**
   - Solution: Run PowerShell as Administrator
   - Right-click PowerShell → Run as Administrator

3. **Scan Failed**
   - Check target accessibility
   - Verify network connectivity
   - Ensure required tools are installed

### Logging
- Check `C:\SecurityTools\Logs\` for detailed logs
- Review Windows Event Logs for system-level issues

## Security Considerations
1. The script requires elevated privileges
2. Some operations may impact system performance
3. Security hardening may affect system functionality
4. Regular backups are recommended
5. Test in a non-production environment first

## Support
For issues and feature requests:
1. Check the troubleshooting section
2. Review the logs
3. Contact system administrator
4. Submit issues through the project repository

## Updates
Regular updates are recommended to:
1. Add new security features
2. Fix known issues
3. Update security checks
4. Improve performance
5. Add new tool integrations

## License
 