# Wireshark Automation Guide

## Overview
This guide explains how to use the Wireshark automation script (`wireshark_automation.ps1`) to automate network traffic capture, analysis, and monitoring tasks. The script provides a user-friendly interface for performing common Wireshark operations and generating detailed reports.

## Prerequisites
- Windows 10 or later
- PowerShell 5.1 or later
- Wireshark installed (default path: `C:\Program Files\Wireshark`)
- PSLogging module installed
- Administrator privileges

## Installation
1. Copy the `wireshark_automation.ps1` script to your desired location
2. Open PowerShell as Administrator
3. Navigate to the script directory
4. Run the script: `.\wireshark_automation.ps1`

## Features

### 1. Packet Capture
- Start packet capture on specified network interface
- Apply custom capture filters
- Set capture duration
- Save captures in PCAPNG format
- Automatic directory creation for captures

### 2. Capture Analysis
- Basic analysis:
  - Protocol distribution
  - Top talkers
  - HTTP statistics
- Security analysis:
  - Suspicious traffic patterns
  - DNS analysis
  - SSL/TLS analysis
- Performance analysis:
  - IO graphs
  - Expert information
  - Round-trip time analysis

### 3. Report Generation
- HTML-based reports with:
  - Capture information
  - Protocol statistics
  - Top talkers
  - HTTP statistics
  - Security analysis results
  - Performance metrics
- Styled output for better readability
- Automatic report organization

### 4. Network Monitoring
- Real-time traffic monitoring
- Custom alert thresholds
- Continuous capture with background processing
- Automatic alert generation for suspicious activity

## Usage

### Starting Packet Capture
1. Select option 1 from the menu
2. Enter the network interface name
3. (Optional) Enter capture filter
4. (Optional) Enter capture duration in seconds
5. The capture will start and save to the specified location

### Analyzing Capture Files
1. Select option 2 from the menu
2. Enter the path to the capture file
3. Choose analysis type:
   - basic: General traffic analysis
   - security: Security-focused analysis
   - performance: Performance metrics
4. Analysis results will be saved in a timestamped directory

### Generating Reports
1. Select option 3 from the menu
2. Enter the capture file path
3. Enter the analysis directory path
4. An HTML report will be generated with all analysis results

### Network Monitoring
1. Select option 4 from the menu
2. Enter the network interface name
3. (Optional) Enter capture filter
4. (Optional) Enter monitoring duration
5. Enter alert threshold (packets per second)
6. Monitoring will start with real-time alerts

## Output Files

### Capture Files
- Location: `C:\SecurityTools\Captures\`
- Format: PCAPNG
- Naming: `capture_YYYY-MM-DD_HH-mm-ss.pcapng`

### Analysis Results
- Location: `C:\SecurityTools\Analysis\YYYY-MM-DD_HH-mm-ss\`
- Files:
  - `protocol_stats.txt`
  - `top_talkers.txt`
  - `http_stats.txt`
  - `suspicious_*.txt`
  - `dns_stats.txt`
  - `ssl_stats.txt`
  - `io_stats.txt`
  - `expert_info.txt`
  - `rtt_stats.txt`

### Reports
- Location: `C:\SecurityTools\Analysis\YYYY-MM-DD_HH-mm-ss\`
- File: `capture_report.html`

### Logs
- Location: `C:\SecurityTools\Logs\`
- Format: `wireshark_automation_YYYY-MM-DD_HH-mm-ss.log`

## Best Practices

### Capture
- Use appropriate capture filters to reduce noise
- Set reasonable capture durations
- Monitor disk space usage
- Use descriptive file names

### Analysis
- Start with basic analysis before diving deep
- Review security analysis results carefully
- Compare performance metrics over time
- Document any suspicious findings

### Monitoring
- Set realistic alert thresholds
- Monitor system resources
- Review alerts promptly
- Document alert patterns

## Troubleshooting

### Common Issues
1. **Permission Denied**
   - Run PowerShell as Administrator
   - Check file permissions
   - Verify Wireshark installation

2. **Interface Not Found**
   - Verify interface name
   - Check interface status
   - Run `ipconfig` to list interfaces

3. **Capture Filter Errors**
   - Verify filter syntax
   - Test filter in Wireshark GUI
   - Check protocol support

4. **Analysis Failures**
   - Verify capture file integrity
   - Check disk space
   - Ensure sufficient memory

### Log Analysis
- Check log files for errors
- Review capture statistics
- Monitor system resources
- Document error patterns

## Security Considerations

### Capture Security
- Use appropriate filters
- Protect capture files
- Monitor disk usage
- Document capture purpose

### Analysis Security
- Review sensitive data
- Protect analysis results
- Document findings
- Follow security policies

### Monitoring Security
- Set appropriate thresholds
- Review alerts promptly
- Document incidents
- Follow response procedures

## Support

### Getting Help
- Review this documentation
- Check log files
- Consult Wireshark documentation
- Contact system administrator

### Reporting Issues
- Document the problem
- Include relevant logs
- Provide capture files
- Describe steps to reproduce

## Updates
- Check for script updates
- Review Wireshark updates
- Update documentation
- Test new features

## License
This script is provided under the MIT License. See the LICENSE file for details. 