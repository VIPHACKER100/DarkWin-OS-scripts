# 🛡️ DarkWin Cloud Security Scanner v2.0

## Overview

DarkWin Cloud Security Scanner v2.0 is an advanced, enterprise-grade PowerShell-based security auditing tool designed for comprehensive cloud infrastructure security assessment. This tool provides automated security scanning across multiple cloud providers (AWS, Azure, GCP), containers, Kubernetes clusters, and Infrastructure as Code (IaC) templates.

## 🚀 Key Features

### Multi-Cloud Support
- **AWS** - Complete security audit using ScoutSuite, Prowler, CloudSploit, CloudMapper
- **Azure** - Comprehensive scanning with AzSK, ScoutSuite, Security Center integration
- **GCP** - Full security assessment using Forseti, ScoutSuite, Security Command Center
- **Multi-Cloud** - Parallel scanning across all providers simultaneously

### Container Security
- Vulnerability scanning with Trivy, Grype, Clair, Syft
- Docker security benchmarking
- Image composition analysis
- CVE detection and reporting

### Kubernetes Security
- CIS Kubernetes Benchmark compliance (kube-bench)
- Security weakness detection (kube-hunter)
- Configuration auditing (kubeaudit)
- Best practices validation (Polaris)
- Runtime security monitoring (Falco)

### Infrastructure as Code (IaC) Security
- Terraform security scanning (tfsec)
- Multi-IaC support (Checkov)
- Policy-as-code validation (Terrascan)
- Cloud configuration security (KICS)
- Dependency vulnerability scanning (Snyk)

### Advanced Capabilities
- Parallel scanning for improved performance
- Compliance framework mapping (CIS, NIST, PCI-DSS, HIPAA, GDPR)
- Multiple export formats (JSON, XML, CSV, HTML)
- Webhook integration for CI/CD pipelines
- Comprehensive HTML reporting with visual analytics
- Severity-based filtering
- Detailed logging and audit trails

## 📋 Prerequisites

### System Requirements
- Windows 10/11 or Windows Server 2016+
- PowerShell 5.1 or higher
- Administrator privileges
- Minimum 4GB RAM (8GB recommended)
- 10GB free disk space

### Required Tools

#### Core Cloud Tools
```
AWS:
- Python 3.8+
- ScoutSuite
- Prowler
- CloudSploit
- CloudMapper
- AWS CLI (optional)

Azure:
- AzSK PowerShell module
- ScoutSuite
- Azure CLI (optional)

GCP:
- Python 3.8+
- Forseti Security
- ScoutSuite
- gcloud CLI (optional)
```

#### Container Security Tools
```
- Trivy
- Grype
- Clair
- Syft (Anchore)
- Docker Bench Security
```

#### Kubernetes Security Tools
```
- kube-bench
- kube-hunter
- kubeaudit
- kubesec
- Polaris
- Falco
```

#### IaC Security Tools
```
- tfsec
- Checkov
- Terrascan
- KICS
- Snyk CLI
```

## 🔧 Installation

### 1. Tool Directory Structure

Create the following directory structure:

```
C:\Tools\
├── Additional\
│   ├── ScoutSuite\
│   ├── Prowler\
│   ├── CloudSploit\
│   ├── CloudMapper\
│   ├── AzSK\
│   ├── Forseti\
│   ├── Trivy\
│   ├── Grype\
│   ├── Clair\
│   ├── Anchore\
│   ├── DockerBench\
│   ├── kube-bench\
│   ├── kube-hunter\
│   ├── kubeaudit\
│   ├── kubesec\
│   ├── Polaris\
│   ├── Falco\
│   ├── tfsec\
│   ├── Checkov\
│   ├── Terrascan\
│   ├── KICS\
│   └── Snyk\
├── Scans\
│   └── Cloud\
└── Logs\
```

### 2. Install Security Tools

#### ScoutSuite (Python)
```powershell
pip install scoutsuite
```

#### Prowler
```powershell
# Download from https://github.com/prowler-cloud/prowler
# Place prowler.exe in C:\Tools\Additional\Prowler\
```

#### Trivy
```powershell
# Download from https://github.com/aquasecurity/trivy/releases
# Place trivy.exe in C:\Tools\Additional\Trivy\
```

#### tfsec
```powershell
# Download from https://github.com/aquasecurity/tfsec/releases
# Place tfsec.exe in C:\Tools\Additional\tfsec\
```

#### Checkov
```powershell
pip install checkov
# Or download binary from https://github.com/bridgecrewio/checkov/releases
```

### 3. Cloud Provider Configuration

#### AWS Configuration
```powershell
# Install AWS CLI
# Configure credentials
aws configure

# Set up profiles
aws configure --profile default
```

#### Azure Configuration
```powershell
# Install Azure CLI
# Login
az login

# Set subscription
az account set --subscription "your-subscription-id"
```

#### GCP Configuration
```powershell
# Install gcloud CLI
# Initialize and authenticate
gcloud init
gcloud auth application-default login
```

## 📖 Usage

### Basic Usage

#### Single Cloud Provider Scan
```powershell
# AWS Scan
.\cloud_security_v2.ps1 -Provider AWS -Region us-east-1

# Azure Scan
.\cloud_security_v2.ps1 -Provider Azure -Region "subscription-id-here"

# GCP Scan
.\cloud_security_v2.ps1 -Provider GCP -Region "project-id-here"
```

### Advanced Usage

#### Multi-Cloud Scan with Parallel Processing
```powershell
.\cloud_security_v2.ps1 `
    -Provider Multi `
    -Region "default" `
    -ParallelScan `
    -ComplianceCheck
```

#### Container Security Scan
```powershell
.\cloud_security_v2.ps1 `
    -Provider AWS `
    -Region us-east-1 `
    -Image "nginx:latest"
```

#### Kubernetes Security Audit
```powershell
.\cloud_security_v2.ps1 `
    -Provider AWS `
    -Region us-east-1 `
    -KubeConfig "C:\Users\Admin\.kube\config"
```

#### Infrastructure as Code Scan
```powershell
.\cloud_security_v2.ps1 `
    -Provider AWS `
    -Region us-east-1 `
    -TerraformDir "C:\Projects\terraform"
```

#### Comprehensive Scan with All Features
```powershell
.\cloud_security_v2.ps1 `
    -Provider Multi `
    -Region "us-east-1" `
    -Image "myapp:latest" `
    -KubeConfig "C:\Users\Admin\.kube\config" `
    -TerraformDir "C:\IaC\terraform" `
    -ParallelScan `
    -ComplianceCheck `
    -SeverityFilter "Critical" `
    -ExportFormat "All" `
    -WebhookURL "https://webhook.site/your-webhook" `
    -OutputDir "C:\SecurityScans" `
    -Verbose
```

## 🎯 Parameters

| Parameter | Type | Required | Description | Default |
|-----------|------|----------|-------------|---------|
| `-Provider` | String | Yes | Cloud provider: AWS, Azure, GCP, Multi | N/A |
| `-Region` | String | Yes | Region or subscription ID | N/A |
| `-Image` | String | No | Container image to scan | N/A |
| `-KubeConfig` | String | No | Kubernetes config path | N/A |
| `-TerraformDir` | String | No | IaC directory path | N/A |
| `-OutputDir` | String | No | Output directory for results | C:\Tools\Scans\Cloud |
| `-SeverityFilter` | String | No | Filter by severity: Critical, High, Medium, Low, All | All |
| `-ParallelScan` | Switch | No | Enable parallel scanning | False |
| `-ExportFormat` | String | No | Export format: JSON, XML, CSV, HTML, All | All |
| `-ComplianceCheck` | Switch | No | Enable compliance checks | False |
| `-WebhookURL` | String | No | Webhook URL for results | N/A |
| `-Verbose` | Switch | No | Enable verbose output | False |

## 📊 Output Format

### Directory Structure
```
C:\Tools\Scans\Cloud\[timestamp]\
├── metadata.json
├── AWS\
│   ├── scoutsuite\
│   ├── prowler.txt
│   ├── cloudsploit.json
│   ├── cloudmapper.html
│   └── security_hub.json
├── Azure\
│   ├── azsk\
│   ├── scoutsuite\
│   ├── cloudsploit.json
│   └── security_center.json
├── GCP\
│   ├── forseti\
│   ├── scoutsuite\
│   ├── cloudsploit.json
│   └── scc_findings.json
├── Container\
│   ├── trivy.json
│   ├── grype.json
│   ├── clair.json
│   ├── syft.json
│   └── docker_bench.log
├── Kubernetes\
│   ├── kube-bench.json
│   ├── kube-hunter.json
│   ├── kubeaudit.json
│   ├── kubesec.json
│   ├── polaris.json
│   └── falco.json
├── Infrastructure\
│   ├── tfsec.json
│   ├── checkov.json
│   ├── terrascan.json
│   ├── kics.json
│   └── snyk.json
└── Reports\
    ├── report.html
    ├── report.json
    ├── report.xml
    ├── findings.csv
    └── compliance.json
```

### Report Contents

#### HTML Report
- Executive summary with visual statistics
- Scan information and metadata
- Detailed findings by severity
- Compliance framework mapping
- Recommendations and remediation steps
- Interactive charts and graphs

#### JSON Report
```json
{
  "Metadata": {
    "Version": "2.0",
    "ScanID": "20260128_143022",
    "Provider": "AWS",
    "Region": "us-east-1",
    "StartTime": "2026-01-28 14:30:22",
    "EndTime": "2026-01-28 14:45:18",
    "Duration": "00:14:56"
  },
  "Statistics": {
    "TotalScans": 5,
    "SuccessfulScans": 5,
    "FailedScans": 0,
    "CriticalFindings": 3,
    "HighFindings": 12,
    "MediumFindings": 45,
    "LowFindings": 67,
    "InfoFindings": 23
  },
  "Findings": []
}
```

## 🔍 Understanding Findings

### Severity Levels

#### Critical (🔴)
- Immediate action required
- Active exploitation possible
- Data breach risk
- Examples: Publicly exposed databases, hardcoded credentials, RCE vulnerabilities

#### High (🟠)
- High priority remediation
- Significant security risk
- Privilege escalation possible
- Examples: Missing encryption, overly permissive IAM policies, unpatched systems

#### Medium (🟡)
- Moderate security concern
- Defense-in-depth issue
- Best practice violation
- Examples: Missing MFA, weak password policies, outdated dependencies

#### Low (🟢)
- Minor security concern
- Configuration improvement
- Security hardening opportunity
- Examples: Missing security headers, verbose error messages, outdated documentation

#### Info (🔵)
- Informational finding
- No immediate risk
- Awareness purposes
- Examples: System inventory, configuration details, version information

## 🛡️ Compliance Frameworks

### Supported Standards
- **CIS** - Center for Internet Security Benchmarks
- **NIST** - National Institute of Standards and Technology
- **PCI-DSS** - Payment Card Industry Data Security Standard
- **HIPAA** - Health Insurance Portability and Accountability Act
- **GDPR** - General Data Protection Regulation
- **SOC 2** - Service Organization Control 2
- **ISO 27001** - Information Security Management

### Compliance Mapping
The tool automatically maps findings to relevant compliance controls:

```powershell
# Example compliance output
{
  "CIS": [
    {
      "Control": "1.14",
      "Description": "Ensure multi-factor authentication is enabled",
      "Status": "FAIL",
      "Findings": [...]
    }
  ],
  "NIST": [...],
  "PCI-DSS": [...]
}
```

## 🔄 CI/CD Integration

### Jenkins Integration
```groovy
pipeline {
    agent any
    stages {
        stage('Security Scan') {
            steps {
                powershell '''
                    .\\cloud_security_v2.ps1 `
                        -Provider AWS `
                        -Region us-east-1 `
                        -TerraformDir "./terraform" `
                        -ComplianceCheck `
                        -WebhookURL "${env.WEBHOOK_URL}"
                '''
            }
        }
    }
    post {
        always {
            archiveArtifacts artifacts: 'C:/Tools/Scans/Cloud/**/Reports/*.html'
            publishHTML([
                reportDir: 'C:/Tools/Scans/Cloud/latest/Reports',
                reportFiles: 'report.html',
                reportName: 'Security Report'
            ])
        }
    }
}
```

### GitLab CI Integration
```yaml
security_scan:
  stage: security
  script:
    - powershell -File cloud_security_v2.ps1 -Provider AWS -Region us-east-1 -ComplianceCheck
  artifacts:
    paths:
      - C:/Tools/Scans/Cloud/*/Reports/
    expire_in: 30 days
  only:
    - main
    - develop
```

### GitHub Actions Integration
```yaml
name: Cloud Security Scan

on:
  push:
    branches: [ main ]
  pull_request:
    branches: [ main ]

jobs:
  security-scan:
    runs-on: windows-latest
    steps:
      - uses: actions/checkout@v3
      
      - name: Run Security Scan
        run: |
          .\cloud_security_v2.ps1 `
            -Provider AWS `
            -Region us-east-1 `
            -TerraformDir "./infrastructure" `
            -ComplianceCheck `
            -WebhookURL ${{ secrets.WEBHOOK_URL }}
      
      - name: Upload Report
        uses: actions/upload-artifact@v3
        with:
          name: security-report
          path: C:/Tools/Scans/Cloud/*/Reports/
```

## 📈 Best Practices

### Scanning Schedule
- **Development**: On every commit/PR
- **Staging**: Daily automated scans
- **Production**: Weekly comprehensive scans
- **Critical Systems**: Daily scans with immediate alerting

### Remediation Priority
1. **Critical**: Immediate (within 24 hours)
2. **High**: Within 1 week
3. **Medium**: Within 30 days
4. **Low**: Within 90 days

### Security Baseline
1. Run initial comprehensive scan
2. Document all findings
3. Create remediation plan
4. Establish acceptance criteria
5. Implement continuous monitoring

## 🔐 Security Considerations

### Credentials Management
- Store cloud credentials securely (AWS Secrets Manager, Azure Key Vault, etc.)
- Use service accounts with minimal permissions
- Rotate credentials regularly
- Never commit credentials to version control

### Tool Permissions
The scanner requires:
- **AWS**: SecurityAudit policy (read-only)
- **Azure**: Security Reader role
- **GCP**: Security Reviewer role
- **Kubernetes**: View permissions on all namespaces

### Scan Safety
- All scans are read-only by default
- No modifications to cloud resources
- Rate limiting to prevent API throttling
- Safe for production environments

## 🐛 Troubleshooting

### Common Issues

#### Issue: Tools not found
**Solution**: Verify tool installation paths match expected locations
```powershell
Test-Path "C:\Tools\Additional\Trivy\trivy.exe"
```

#### Issue: Authentication failures
**Solution**: Verify cloud provider credentials
```powershell
# AWS
aws sts get-caller-identity

# Azure
az account show

# GCP
gcloud auth list
```

#### Issue: Permission denied errors
**Solution**: Run PowerShell as Administrator
```powershell
# Check if running as admin
([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
```

#### Issue: Scan taking too long
**Solution**: Use parallel scanning or filter by severity
```powershell
.\cloud_security_v2.ps1 -Provider AWS -Region us-east-1 -ParallelScan -SeverityFilter Critical
```

## 📚 Additional Resources

### Official Documentation
- [AWS Security Best Practices](https://aws.amazon.com/security/best-practices/)
- [Azure Security Documentation](https://docs.microsoft.com/en-us/azure/security/)
- [GCP Security Documentation](https://cloud.google.com/security)
- [CIS Benchmarks](https://www.cisecurity.org/cis-benchmarks/)

### Tool Documentation
- [ScoutSuite](https://github.com/nccgroup/ScoutSuite)
- [Prowler](https://github.com/prowler-cloud/prowler)
- [Trivy](https://aquasecurity.github.io/trivy/)
- [kube-bench](https://github.com/aquasecurity/kube-bench)
- [tfsec](https://aquasecurity.github.io/tfsec/)
- [Checkov](https://www.checkov.io/)

## 🤝 Contributing

### Reporting Issues
Please report issues with:
- PowerShell version
- Cloud provider and region
- Full error message
- Steps to reproduce

### Feature Requests
We welcome feature requests for:
- Additional cloud providers
- New security tools
- Enhanced reporting
- Integration options

## 📝 Changelog

### Version 2.0 (2026-01-28)
- ✨ Complete rewrite with modular architecture
- 🚀 Multi-cloud parallel scanning support
- 📊 Enhanced HTML reporting with visual analytics
- 🔍 Added 15+ new security scanning tools
- 🎯 Compliance framework mapping (CIS, NIST, PCI-DSS, HIPAA, GDPR)
- 🔗 Webhook integration for CI/CD pipelines
- 📤 Multiple export formats (JSON, XML, CSV, HTML)
- 🎨 Improved error handling and logging
- ⚡ Performance optimizations
- 🛡️ Container and Kubernetes security scanning
- 🏗️ Infrastructure as Code security validation

### Version 1.0 (Previous)
- Basic cloud security scanning
- Support for AWS, Azure, GCP
- Simple HTML reporting
- Limited tool integration

## 📄 License

This tool is provided as-is for security testing purposes. Use responsibly and in accordance with your organization's security policies and applicable laws.

## ⚠️ Disclaimer

This tool is designed for authorized security testing only. Users are responsible for:
- Obtaining proper authorization before scanning
- Complying with applicable laws and regulations
- Using findings responsibly
- Protecting sensitive scan data

**Never use this tool on systems you don't own or have explicit permission to test.**

## 📞 Support

For support, questions, or feedback:
- Create an issue in the repository
- Contact your security team
- Review the troubleshooting section
- Check tool-specific documentation

---

**DarkWin Cloud Security Scanner v2.0** | Securing Cloud Infrastructure One Scan at a Time 🛡️

*Last Updated: January 28, 2026*
