# Contributing to CyberMailConnect

Thank you for your interest in contributing to CyberMailConnect! This document provides guidelines for contributing to the project.

## Code of Conduct

- Be respectful and professional
- Focus on constructive feedback
- Help create a welcoming environment
- Report security issues responsibly

## How to Contribute

### Reporting Bugs

Before reporting a bug:
1. Check existing issues
2. Verify you're using the latest version
3. Test with minimal configuration

When reporting:
```markdown
**Environment:**
- Python version:
- OS:
- CyberMailConnect version:

**Steps to Reproduce:**
1. Step 1
2. Step 2

**Expected Behavior:**
What should happen

**Actual Behavior:**
What actually happens

**Error Messages:**
```python
Full traceback here
```
```

### Suggesting Features

Feature requests should include:
- Clear use case
- Expected behavior
- Example code or pseudocode
- Security considerations

### Contributing Code

#### Getting Started

1. Fork the repository
2. Clone your fork
3. Create a feature branch
4. Make your changes
5. Test thoroughly
6. Submit a pull request

```bash
git clone https://github.com/yourusername/CyberMailConnect.git
cd CyberMailConnect
git checkout -b feature/your-feature-name
```

#### Code Standards

**Python Style:**
- Follow PEP 8
- Use type hints where appropriate
- Write docstrings for all public functions
- Keep functions focused and small

Example:
```python
def validate_domain(self, domain: str) -> ValidationResult:
    """
    Validate SPF record for a domain.

    Args:
        domain: Domain name to check

    Returns:
        ValidationResult with validation status
    """
    # Implementation
    pass
```

**Security:**
- Never commit credentials
- Sanitize user input
- Validate all external data
- Use secure defaults
- Document security implications

**Testing:**
- Write unit tests for new features
- Maintain test coverage
- Test edge cases
- Include integration tests where appropriate

```python
def test_new_feature(self):
    """Test description."""
    # Arrange
    connector = MailConnector("test.com")

    # Act
    result = connector.new_feature()

    # Assert
    self.assertTrue(result)
```

#### Running Tests

```bash
# Run all tests
python -m pytest tests/

# Run specific test file
python -m pytest tests/test_connector.py

# Run with coverage
python -m pytest --cov=cybermailconnect tests/
```

#### Documentation

- Update README.md if adding features
- Add docstrings to new code
- Update API documentation (docs/api.md)
- Include examples where helpful

### Pull Request Process

1. **Before Submitting:**
   - Run all tests
   - Update documentation
   - Follow code style guidelines
   - Squash trivial commits

2. **PR Description Should Include:**
   - What changes were made
   - Why the changes were needed
   - How to test the changes
   - Related issues (if any)

3. **PR Template:**
```markdown
## Description
Brief description of changes

## Motivation
Why is this change needed?

## Testing
How was this tested?

## Checklist
- [ ] Tests pass
- [ ] Documentation updated
- [ ] Code follows style guidelines
- [ ] No sensitive data committed
```

## Development Setup

### Prerequisites

- Python 3.8 or higher
- pip
- virtualenv (recommended)

### Setup Development Environment

```bash
# Create virtual environment
python -m venv venv
source venv/bin/activate  # On Windows: venv\Scripts\activate

# Install dependencies
pip install -r requirements.txt

# Install development dependencies
pip install pytest pytest-cov black flake8 mypy

# Install in development mode
pip install -e .
```

### Development Tools

**Code Formatting:**
```bash
# Format code with black
black cybermailconnect/

# Check formatting
black --check cybermailconnect/
```

**Linting:**
```bash
# Run flake8
flake8 cybermailconnect/

# Run mypy for type checking
mypy cybermailconnect/
```

## Security

### Responsible Disclosure

If you discover a security vulnerability:

1. **DO NOT** open a public issue
2. Email the maintainers privately
3. Provide detailed description
4. Allow time for fix before disclosure

### Security Considerations for Contributors

- Never include real credentials in examples
- Use example.com for test domains
- Sanitize all logs in tests
- Document security implications of changes
- Follow principle of least privilege

## Project Structure

```
CyberMailConnect/
├── cybermailconnect/     # Main package
│   ├── __init__.py       # Package initialization
│   ├── connector.py      # Connection handling
│   ├── security_analyzer.py
│   ├── header_parser.py
│   ├── validators.py
│   └── auth.py
├── examples/             # Example scripts
├── tests/                # Test suite
├── docs/                 # Documentation
├── README.md
├── LICENSE
├── requirements.txt
└── setup.py
```

## Release Process

Maintainers handle releases:

1. Update version in `__init__.py` and `setup.py`
2. Update CHANGELOG
3. Create release tag
4. Build and publish to PyPI

## Getting Help

- Check documentation in docs/
- Review existing issues
- Ask in discussions (if enabled)
- Email maintainers for sensitive topics

## License

By contributing, you agree that your contributions will be licensed under the MIT License.

## Recognition

Contributors will be recognized in:
- CONTRIBUTORS.md (if created)
- Release notes
- Project README

Thank you for contributing to CyberMailConnect!
