# OWASP ZAP Automation Guide

## Overview
This guide explains how to use the OWASP ZAP automation script to automate web application security testing and vulnerability scanning tasks.

## Prerequisites
- Windows 10 or later
- PowerShell 5.1 or later
- OWASP ZAP
- Administrative privileges
- PSLogging module

## Features

### 1. OWASP ZAP Management
- Start OWASP ZAP with custom configuration
- Configure proxy settings
- Manage session files

### 2. Security Scanning
- Quick scanning
- Full scanning
- API scanning
- Custom scan configurations

### 3. Report Generation
- HTML report generation
- Custom report templates
- Scan result documentation

## Usage

### Running the Script
1. Open PowerShell as Administrator
2. Navigate to the script directory
3. Execute the script:
   ```powershell
   .\zap_automation.ps1
   ```

### Menu Options
1. **Start OWASP ZAP**
   - Launches OWASP ZAP with custom configuration
   - Uses default config file or specified config

2. **Start Quick Scan**
   - Performs rapid security scan
   - Generates session file and report
   - Requires target URL

3. **Start Full Scan**
   - Performs comprehensive security scan
   - Includes vulnerability testing
   - Generates detailed report
   - Requires target URL

4. **Start API Scan**
   - Performs API security scan
   - Tests API endpoints
   - Generates API-specific report
   - Requires target URL

5. **Generate Report**
   - Creates HTML report from session file
   - Includes scan findings
   - Requires session file path

6. **Configure Proxy**
   - Sets up OWASP ZAP proxy
   - Configures interface and port
   - Updates configuration file

## Output Files

### Session Files
- Location: `C:\SecurityTools\Projects\`
- Format: `.session`
- Naming: `zap_[scan_type]_[timestamp].session`

### Reports
- Location: `C:\SecurityTools\Reports\`
- Format: `.html`
- Naming: `zap_[scan_type]_[timestamp].html`

### Logs
- Location: `C:\SecurityTools\Logs\`
- Format: `.log`
- Naming: `zap_automation_[timestamp].log`

## Best Practices

### Scanning
1. Start with quick scans
2. Use full scans for critical systems
3. Monitor system resources
4. Document scan parameters

### Proxy Configuration
1. Use secure interfaces
2. Change default ports
3. Enable SSL inspection
4. Monitor proxy logs

### Report Management
1. Review reports promptly
2. Archive old reports
3. Share findings securely
4. Document remediation steps

## Troubleshooting

### Common Issues
1. **OWASP ZAP Not Starting**
   - Check installation path
   - Verify configuration file
   - Check system resources

2. **Scan Failures**
   - Verify target accessibility
   - Check proxy settings
   - Review error logs

3. **Report Generation Issues**
   - Verify session file existence
   - Check file permissions
   - Review disk space

### Log Analysis
- Check `C:\SecurityTools\Logs\` for detailed logs
- Review error messages
- Monitor system events

## Security Considerations

### Data Protection
1. Secure session files
2. Encrypt sensitive data
3. Control report access
4. Monitor log files

### Network Security
1. Use secure connections
2. Monitor proxy traffic
3. Control scan scope
4. Document network impact

## Support

### Getting Help
1. Review this guide
2. Check log files
3. Contact support
4. Submit issues

### Updates
- Regular updates may include:
  - New scan types
  - Enhanced reporting
  - Performance improvements
  - Bug fixes

## License
This script is provided under the MIT License. See the LICENSE file for details. 