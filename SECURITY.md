# Security Policy

## Reporting a Vulnerability

We greatly value the efforts of the community in identifying and responsibly disclosing security vulnerabilities. Your contributions help us ensure the safety and reliability of our software.

If you have discovered a vulnerability in one of our products or have security concerns regarding AGILira software, please contact us at **security@agilira.com**.

To help us address your report effectively, please include the following details:

- **Steps to Reproduce**: A clear and concise description of how to reproduce the issue or a proof-of-concept.
- **Relevant Tools**: Any tools used during your investigation, including their versions.
- **Tool Output**: Logs, screenshots, or any other output that supports your findings.

For more information about AGILira's security practices, please visit our [Security Page](https://agilira.one/security).

Thank you for helping us maintain a secure and trustworthy environment for all users.

## Security Testing and Fuzz Testing

### Overview

The Argus Consul Provider undergoes comprehensive security testing including static analysis, dynamic testing, and **fuzz testing** to identify potential vulnerabilities and ensure robust security in production environments.

### Fuzz Testing Implementation

This provider includes comprehensive fuzz testing implemented with Go's native fuzzing framework (Go 1.18+) to test critical security boundaries:

#### Fuzz Test Functions

1. **`FuzzParseConsulURL`** - Tests Consul URL parsing security
   - **Attack Surface**: URL parsing and validation
   - **Security Coverage**: SSRF prevention, authentication bypass detection, credential exposure prevention
   - **Seed Corpus**: Real-world attack vectors including path traversal, host manipulation, and protocol confusion

2. **`FuzzValidateSecureKeyPath`** - Tests path traversal prevention  
   - **Attack Surface**: Consul key path validation
   - **Security Coverage**: Directory traversal attacks, Windows device name exploitation, URL encoding bypass
   - **Seed Corpus**: Known path traversal patterns, Windows device names, encoded attacks

3. **`FuzzConsulJSONParsing`** - Tests JSON parser resilience
   - **Attack Surface**: JSON parsing from Consul responses
   - **Security Coverage**: Memory exhaustion prevention, parser DoS protection, malformed data handling
   - **Seed Corpus**: Oversized responses, deeply nested objects, malformed JSON

4. **`FuzzConsulLoad`** - Tests end-to-end Load function
   - **Attack Surface**: Complete configuration loading process
   - **Security Coverage**: Integrated security validation, error handling safety
   - **Seed Corpus**: Malicious URLs, invalid configurations, edge cases

### Running Fuzz Tests

#### Quick Fuzz Testing (30 seconds each test)
```bash
make fuzz
```

#### Extended Fuzz Testing (5 minutes each test - recommended for CI)
```bash 
make fuzz-extended
```

#### Continuous Fuzz Testing (until interrupted)
```bash
make fuzz-continuous
```

#### Security-Focused CI Pipeline
```bash
make ci-security  # Includes static analysis + fuzz testing
```

### Interpreting Fuzz Test Results

#### Successful Fuzz Run
```
fuzz: elapsed: 30s, gathering baseline coverage: 0s, corpus: 156 (now: 156), crashers: 0
```
- **No crashers**: All inputs handled safely
- **Corpus growth**: Fuzzer found new interesting inputs
- **Baseline coverage**: Code paths exercised

#### Fuzz Failure Indicators
```
fuzz: elapsed: 5s, gathering baseline coverage: 0s, corpus: 23 (now: 23), crashers: 1
```
- **crashers > 0**: Security vulnerability or crash found
- **Check testdata/fuzz/**: Contains failing inputs
- **Review crash logs**: Identify root cause

#### Security Invariant Violations
Look for these patterns in fuzz output:
- `SECURITY VIOLATION:` - Critical security boundary bypassed
- `SECURITY LEAK:` - Information disclosure detected  
- `PERFORMANCE WARNING:` - Potential DoS condition
- `RESOURCE VIOLATION:` - Memory/resource exhaustion

### Fuzz Test Security Coverage

#### URL Parsing Security (parseConsulURL)
- **SSRF Prevention**: Blocks connections to internal services (127.0.0.1:22, 169.254.169.254)
- **Authentication Bypass**: Prevents token/credential manipulation
- **Host Header Injection**: Validates host format and prevents confusion attacks
- **Protocol Confusion**: Enforces consul:// scheme requirement
- **Credential Exposure**: Ensures passwords/tokens don't leak in error messages

#### Path Validation Security (validateSecureKeyPath)
- **Directory Traversal**: Blocks ../, ..\, and URL-encoded variants
- **Windows Device Names**: Prevents CON, PRN, COM1, LPT1, etc. exploitation
- **Null Byte Injection**: Detects \x00 and control characters
- **Path Length Limits**: Enforces reasonable path size constraints
- **Normalization Attacks**: Handles complex encoding combinations

#### JSON Parser Security (JSON parsing)
- **Memory Exhaustion**: Limits response size and parsing time
- **Nested Object DoS**: Detects deeply nested JSON structures
- **Large Array DoS**: Handles oversized array responses
- **Malformed Data**: Gracefully handles invalid JSON
- **Control Character Injection**: Filters dangerous characters in keys/values

### Security Testing Best Practices

1. **Regular Execution**: Run fuzz tests in CI/CD pipeline for every commit
2. **Extended Testing**: Use `fuzz-extended` for security-critical releases  
3. **Continuous Monitoring**: Run `fuzz-continuous` during security audits
4. **Corpus Maintenance**: Review and update seed corpus with new attack vectors
5. **Failure Investigation**: Immediately investigate any fuzz failures or crashes

### Integration with Red Team Testing

Fuzz testing complements red team security analysis:
- **Static Analysis**: gosec, staticcheck for code-level vulnerabilities
- **Vulnerability Scanning**: govulncheck for known CVEs in dependencies
- **Dynamic Testing**: Fuzz testing for runtime behavior validation  
- **Red Team Testing**: Manual security assessment and penetration testing
- **Integration Testing**: End-to-end security validation in realistic environments

### Continuous Security Improvement

The fuzz testing suite is continuously enhanced based on:
- **Security Research**: New attack vectors and techniques
- **Vulnerability Disclosures**: Real-world Consul security issues
- **Red Team Findings**: Results from security assessments
- **Community Contributions**: External security research and reports

For security issues found through fuzz testing or other means, please follow the vulnerability reporting process above.

---

argus-provider-consul • an AGILira library