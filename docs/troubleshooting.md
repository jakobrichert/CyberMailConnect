# Troubleshooting Guide

## Common Issues and Solutions

### Connection Issues

#### Issue: "Connection timeout"

**Symptoms:**
```
TimeoutError: Connection timed out
```

**Possible Causes:**
1. Firewall blocking connection
2. Incorrect hostname or port
3. Server not responding
4. Network connectivity issues

**Solutions:**
```python
# Increase timeout
connector = MailConnector(
    host="mail.example.com",
    timeout=60  # Increase from default 30
)

# Test basic connectivity
import socket
sock = socket.socket()
sock.settimeout(10)
result = sock.connect_ex(("mail.example.com", 587))
if result == 0:
    print("Port is reachable")
```

#### Issue: "SSL certificate verification failed"

**Symptoms:**
```
ssl.SSLCertVerificationError: certificate verify failed
```

**Possible Causes:**
1. Self-signed certificate
2. Expired certificate
3. Hostname mismatch
4. Missing intermediate certificates

**Solutions:**
```python
# For testing only - disable verification
connector = MailConnector(
    host="mail.example.com",
    verify_cert=False  # Use only for testing!
)

# Check certificate details
cert = connector.get_ssl_certificate()
print(cert)
```

#### Issue: "Connection refused"

**Symptoms:**
```
ConnectionRefusedError: [Errno 111] Connection refused
```

**Possible Causes:**
1. Wrong port number
2. Service not running
3. Firewall blocking

**Solutions:**
```python
# Try scanning all ports
results = connector.scan_ports()
for result in results:
    if result.connected:
        print(f"Found service on port {result.port}")
```

### DNS Issues

#### Issue: "DNS resolution failed"

**Symptoms:**
```
dns.resolver.NXDOMAIN: The DNS query name does not exist
```

**Solutions:**
```python
# Check DNS manually
import dns.resolver

resolver = dns.resolver.Resolver()
resolver.nameservers = ['8.8.8.8']  # Use Google DNS

try:
    answers = resolver.resolve('example.com', 'TXT')
    for rdata in answers:
        print(rdata)
except Exception as e:
    print(f"DNS error: {e}")
```

#### Issue: "SPF/DKIM/DMARC records not found"

**Possible Causes:**
1. Records not configured
2. DNS propagation delay
3. Wrong domain name

**Solutions:**
```bash
# Test with dig/nslookup
dig example.com TXT
dig _dmarc.example.com TXT
dig default._domainkey.example.com TXT
```

### Authentication Issues

#### Issue: "Authentication failed"

**Symptoms:**
```
smtplib.SMTPAuthenticationError: (535, b'Authentication failed')
```

**Possible Causes:**
1. Wrong credentials
2. Account locked
3. Two-factor authentication required
4. App-specific password needed

**Solutions:**
```python
# For Gmail/Google Workspace
# 1. Enable "Less secure app access" OR
# 2. Generate app-specific password

# For Office 365
# 1. Enable SMTP AUTH in admin center
# 2. Use modern authentication
```

### Import Errors

#### Issue: "No module named 'dnspython'"

**Solution:**
```bash
pip install -r requirements.txt
```

#### Issue: "ImportError: cannot import name 'MailConnector'"

**Possible Causes:**
1. Package not installed
2. Wrong Python path
3. Circular imports

**Solutions:**
```bash
# Install in development mode
pip install -e .

# Or add to PYTHONPATH
export PYTHONPATH="${PYTHONPATH}:/path/to/CyberMailConnect"
```

### Performance Issues

#### Issue: "Scans taking too long"

**Solutions:**
```python
# Reduce number of ports
connector.SMTP_PORTS = [587]  # Test only submission port

# Increase timeout
connector.timeout = 10  # Reduce from 30

# Limit concurrent operations
import threading
semaphore = threading.Semaphore(3)  # Max 3 concurrent
```

### Python Version Issues

#### Issue: "SyntaxError: invalid syntax"

**Possible Causes:**
- Using Python < 3.8
- Missing f-string support

**Solution:**
```bash
# Check Python version
python --version

# Should be 3.8 or higher
# Upgrade if necessary
```

## Debugging Tips

### Enable Debug Logging

```python
import logging

logging.basicConfig(
    level=logging.DEBUG,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
)
```

### Capture Network Traffic

For deep debugging, capture network traffic:

```bash
# Using tcpdump (Linux/Mac)
sudo tcpdump -i any -w mail_traffic.pcap port 587

# Using Wireshark
# 1. Start capture on network interface
# 2. Filter: tcp.port == 587
# 3. Analyze SMTP conversation
```

### Test with OpenSSL

```bash
# Test SMTP with STARTTLS
openssl s_client -connect mail.example.com:587 -starttls smtp

# Test SMTPS (implicit SSL)
openssl s_client -connect mail.example.com:465

# Test IMAPS
openssl s_client -connect mail.example.com:993
```

### Test with Telnet

```bash
# Basic SMTP test
telnet mail.example.com 25

# Commands to try:
# EHLO test.com
# MAIL FROM:<test@test.com>
# QUIT
```

## Error Messages Reference

| Error | Meaning | Solution |
|-------|---------|----------|
| 421 | Service not available | Temporary issue, retry later |
| 450 | Mailbox unavailable | Temporary issue, retry |
| 451 | Local error | Server configuration issue |
| 452 | Insufficient storage | Server out of space |
| 500 | Syntax error | Check command format |
| 502 | Command not implemented | Feature not supported |
| 503 | Bad sequence | Send commands in correct order |
| 550 | Mailbox unavailable | Permanent failure |
| 551 | User not local | Relay issue |
| 552 | Storage exceeded | Message too large |
| 553 | Mailbox name invalid | Invalid recipient |
| 554 | Transaction failed | Permanent failure |

## Getting Help

### Before Asking for Help

1. Check this troubleshooting guide
2. Review the API documentation
3. Enable debug logging
4. Test with standard tools (telnet, openssl)
5. Check server logs if available

### Reporting Issues

Include:
1. Python version
2. Operating system
3. Complete error message
4. Minimal code to reproduce
5. Debug logs (remove sensitive info)

### Community Resources

- GitHub Issues: Report bugs and request features
- Security Issues: Report privately to maintainers
- Documentation: Check docs/ directory

## Performance Optimization

### Reduce DNS Queries

```python
# Cache DNS results
from functools import lru_cache

@lru_cache(maxsize=128)
def cached_dns_lookup(domain):
    # Your DNS lookup code
    pass
```

### Connection Pooling

For multiple tests on same server:

```python
# Reuse connector
connector = MailConnector("mail.example.com")

# Run multiple tests
result1 = connector.test_smtp_connection()
result2 = analyzer.run_full_scan()
# etc.
```

### Parallel Scanning

```python
from concurrent.futures import ThreadPoolExecutor

def scan_host(host):
    connector = MailConnector(host)
    return connector.scan_ports()

hosts = ["mail1.example.com", "mail2.example.com"]

with ThreadPoolExecutor(max_workers=5) as executor:
    results = executor.map(scan_host, hosts)
```
