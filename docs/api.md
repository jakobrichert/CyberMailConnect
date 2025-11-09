# API Reference

## MailConnector

The main connector class for establishing email server connections.

### Constructor

```python
MailConnector(
    host: str,
    port: int = 587,
    use_tls: bool = True,
    verify_cert: bool = True,
    timeout: int = 30,
    min_tls_version: str = "TLSv1_2"
)
```

**Parameters:**
- `host`: Mail server hostname
- `port`: Port number (default: 587)
- `use_tls`: Enable TLS/SSL encryption
- `verify_cert`: Verify SSL certificates
- `timeout`: Connection timeout in seconds
- `min_tls_version`: Minimum TLS version ("TLSv1_2" or "TLSv1_3")

### Methods

#### test_smtp_connection()

Test SMTP connection and gather server information.

**Returns:** `ConnectionInfo` object

```python
connector = MailConnector("mail.example.com", 587)
result = connector.test_smtp_connection()
```

#### test_imap_connection()

Test IMAP connection and gather server information.

**Returns:** `ConnectionInfo` object

#### test_pop3_connection()

Test POP3 connection and gather server information.

**Returns:** `ConnectionInfo` object

#### scan_ports()

Scan common mail ports and test connections.

**Returns:** List of `ConnectionInfo` objects

```python
results = connector.scan_ports()
for result in results:
    print(f"{result.protocol} on port {result.port}: {result.connected}")
```

#### get_ssl_certificate()

Retrieve SSL certificate information.

**Returns:** Dictionary with certificate details

---

## SecurityAnalyzer

Comprehensive security analyzer for mail servers.

### Constructor

```python
SecurityAnalyzer(connector: MailConnector)
```

**Parameters:**
- `connector`: MailConnector instance to analyze

### Methods

#### run_full_scan()

Execute complete security analysis.

**Returns:** `ScanResult` object

```python
analyzer = SecurityAnalyzer(connector)
results = analyzer.run_full_scan()
```

#### generate_report()

Generate human-readable security report.

**Returns:** String containing formatted report

```python
print(analyzer.generate_report())
```

---

## HeaderParser

Parse and analyze email headers for security issues.

### Methods

#### parse(raw_headers: str)

Parse email headers and perform security analysis.

**Returns:** `HeaderAnalysis` object

```python
parser = HeaderParser()
analysis = parser.parse(email_headers)
```

#### generate_report()

Generate human-readable analysis report.

**Returns:** String containing formatted report

---

## Validators

### SPFValidator

Validate SPF records.

```python
validator = SPFValidator()
result = validator.validate_domain("example.com")
```

### DKIMValidator

Validate DKIM records.

```python
validator = DKIMValidator()
result = validator.validate_selector("example.com", "default")
```

### DMARCValidator

Validate DMARC policies.

```python
validator = DMARCValidator()
result = validator.validate_domain("example.com")
```

---

## Data Classes

### ConnectionInfo

```python
@dataclass
class ConnectionInfo:
    host: str
    port: int
    protocol: str
    tls_version: Optional[str] = None
    cipher: Optional[str] = None
    certificate: Optional[Dict] = None
    connected: bool = False
    banner: Optional[str] = None
    capabilities: List[str] = None
```

### ScanResult

```python
@dataclass
class ScanResult:
    vulnerabilities: List[Vulnerability] = []
    passed_checks: List[str] = []
    server_info: Dict = {}
    scan_duration: float = 0.0
```

### Vulnerability

```python
@dataclass
class Vulnerability:
    title: str
    description: str
    severity: Severity
    affected_component: str
    recommendation: str
    cve: Optional[str] = None
    references: List[str] = []
```

### ValidationResult

```python
@dataclass
class ValidationResult:
    valid: bool
    details: str
    record: Optional[str] = None
    errors: List[str] = None
```

---

## Enumerations

### Severity

```python
class Severity(Enum):
    CRITICAL = "CRITICAL"
    HIGH = "HIGH"
    MEDIUM = "MEDIUM"
    LOW = "LOW"
    INFO = "INFO"
```

### AuthMethod

```python
class AuthMethod(Enum):
    PLAIN = "PLAIN"
    LOGIN = "LOGIN"
    CRAM_MD5 = "CRAM-MD5"
    OAUTH2 = "OAUTH2"
    XOAUTH2 = "XOAUTH2"
```
