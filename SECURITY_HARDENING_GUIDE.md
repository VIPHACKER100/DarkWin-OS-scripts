# Security Hardening Guide

## Overview
This guide provides detailed information about the security hardening script (`security_hardening.ps1`) that enhances the security of Windows systems through various configurations and settings.

## Prerequisites
- Windows 10 or later
- PowerShell 5.1 or later
- Administrative privileges
- Required PowerShell modules:
  - PSLogging
  - NetSecurity
  - Defender
  - SecurityPolicy

## Features

### 1. Windows Defender Configuration
- Enables real-time protection
- Configures cloud protection settings
- Sets up tamper protection
- Configures scan schedules
- Manages exclusions for security tools

### 2. Firewall Configuration
- Enables and configures Windows Firewall
- Sets default profiles (Private, Public, Domain)
- Configures logging settings
- Implements security rules:
  - Blocks remote management (RDP)
  - Blocks SMB
  - Allows ICMP for network diagnostics

### 3. System Security
- Configures User Account Control (UAC)
- Implements password policies:
  - Minimum length: 12 characters
  - Maximum age: 90 days
  - Minimum age: 1 day
  - Password history: 24 passwords
- Configures account lockout:
  - Threshold: 5 attempts
  - Duration: 30 minutes
  - Window: 30 minutes
- Disables unnecessary services
- Implements registry security settings

### 4. Network Security
- Disables NetBIOS
- Disables LLMNR
- Configures DNS settings
- Implements TCP/IP security settings:
  - PMTU Discovery
  - TCP Attack Protection
  - Connection retransmission limits
  - TCP timing parameters

### 5. Audit Policy
- Enables comprehensive auditing
- Configures specific audit policies for:
  - Credential validation
  - Security group management
  - User account management
  - Process creation
  - Directory service access
  - Account logon

## Usage

1. Open PowerShell as Administrator
2. Navigate to the script directory
3. Run the script:
```powershell
.\security_hardening.ps1
```

## Output Files

### Logs
- Security hardening log: `C:\SecurityTools\Logs\security_hardening_[timestamp].log`
- Firewall log: `C:\SecurityTools\Logs\firewall.log`

## Best Practices

1. **Backup**
   - Create a system restore point before running the script
   - Backup important data and configurations

2. **Testing**
   - Test the script in a non-production environment first
   - Verify all security tools and services function correctly

3. **Monitoring**
   - Monitor system performance after applying changes
   - Review logs for any issues or conflicts

4. **Maintenance**
   - Regularly review and update security settings
   - Keep security tools and modules updated

## Troubleshooting

### Common Issues

1. **Module Not Found**
   - Install required PowerShell modules:
   ```powershell
   Install-Module -Name PSLogging,NetSecurity,Defender,SecurityPolicy -Force
   ```

2. **Access Denied**
   - Ensure running PowerShell as Administrator
   - Check user permissions

3. **Service Conflicts**
   - Review disabled services list
   - Enable required services if needed

4. **Network Issues**
   - Verify network connectivity
   - Check firewall rules
   - Review DNS settings

### Log Analysis
- Check the security hardening log for detailed information
- Review firewall logs for blocked connections
- Monitor Windows Event Logs for related events

## Security Considerations

1. **Privileges**
   - Script requires administrative privileges
   - Review and understand all changes before applying

2. **Impact**
   - Some settings may affect system performance
   - Certain applications may require adjustments

3. **Compliance**
   - Verify settings align with organizational policies
   - Document all changes for audit purposes

## Support

For issues or questions:
1. Review the troubleshooting section
2. Check the logs for detailed error information
3. Contact system administrator or security team

## Updates

Regular updates may include:
- New security features
- Updated configurations
- Bug fixes
- Performance improvements

## License

This script is provided under the MIT License. See LICENSE file for details. 