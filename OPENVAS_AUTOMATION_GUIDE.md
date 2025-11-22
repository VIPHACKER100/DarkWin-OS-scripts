# OpenVAS Automation Guide

## Overview
This guide explains how to use the OpenVAS automation script to automate vulnerability scanning and security assessment tasks.

## Prerequisites
- Windows 10 or later
- PowerShell 5.1 or later
- OpenVAS (Greenbone Vulnerability Management)
- Administrative privileges
- PSLogging module
- security_logging module

## Features

### 1. OpenVAS Server Management
- Connect to OpenVAS server
- API key or username/password authentication
- Server configuration management

### 2. Security Scanning
- Full vulnerability scanning
- Compliance scanning
- Custom scan configurations
- Scan status monitoring

### 3. Report Generation
- HTML report generation
- PDF report generation
- XML report generation
- Custom report formats

## Usage

### Running the Script
1. Open PowerShell as Administrator
2. Navigate to the script directory
3. Execute the script:
   ```powershell
   .\openvas_automation.ps1
   ```

### Menu Options
1. **Connect to OpenVAS Server**
   - Connect using API key
   - Connect using username/password
   - Configure server settings

2. **Start Full Scan**
   - Perform comprehensive scan
   - Use default configuration
   - Generate detailed report

3. **Start Compliance Scan**
   - Perform compliance check
   - Use compliance configuration
   - Generate compliance report

4. **Get Scan Status**
   - Check scan progress
   - View scan details
   - Monitor scan completion

5. **Generate Report**
   - Create HTML report
   - Create PDF report
   - Create XML report
   - Custom report formats

6. **List Scan Configs**
   - View available configurations
   - Configuration details
   - Configuration management

## Output Files

### Scan Results
- Location: `C:\SecurityTools\Reports\`
- Format: `.html`, `.pdf`, `.xml`
- Naming: `openvas_scan_[scan_id]_[timestamp].[format]`

### Logs
- Location: `C:\SecurityTools\Logs\`
- Format: `.log`
- Naming: `openvas_automation_[timestamp].log`

## Best Practices

### Scanning
1. Start with full scans
2. Use compliance scans for specific checks
3. Monitor scan resources
4. Document scan parameters

### Report Management
1. Review reports promptly
2. Archive old reports
3. Share findings securely
4. Document remediation steps

### Security
1. Use API keys when possible
2. Secure credentials
3. Control access to reports
4. Monitor scan impact

## Troubleshooting

### Common Issues
1. **Connection Failures**
   - Check server URL
   - Verify credentials
   - Check network connectivity
   - Review server status

2. **Scan Failures**
   - Verify target accessibility
   - Check scan configuration
   - Review error logs
   - Monitor resources

3. **Report Generation Issues**
   - Check scan completion
   - Verify file permissions
   - Review disk space
   - Check format support

### Log Analysis
- Check `C:\SecurityTools\Logs\` for detailed logs
- Review error messages
- Monitor system events
- Track scan progress

## Security Considerations

### Data Protection
1. Secure scan results
2. Encrypt sensitive data
3. Control report access
4. Monitor log files

### Network Security
1. Use secure connections
2. Monitor scan traffic
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