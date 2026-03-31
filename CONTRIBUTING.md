# Contributing to repo-security-scanner

Thanks for your interest in contributing! This guide will help you get started.

## Getting Started

```bash
# Clone the repo
git clone https://github.com/yashbarot/security-scanner.git
cd security-scanner

# Install in development mode
pip install -e ".[dev]"

# Run tests
pytest
```

## How to Contribute

### Reporting Bugs

Open an issue at [GitHub Issues](https://github.com/yashbarot/security-scanner/issues) with:
- What you expected to happen
- What actually happened
- Steps to reproduce
- Your Python version and OS

### Adding a New Ecosystem Parser

This is the most common contribution. To add support for a new package ecosystem:

1. Add the ecosystem to `src/repo_security_scanner/models.py`:
   ```python
   class Ecosystem(Enum):
       # ...existing...
       YOUR_ECO = "YourEcosystem"
   ```

2. Create `src/repo_security_scanner/parsers/your_eco.py`:
   ```python
   from repo_security_scanner.parsers.base import DependencyParser, register_parser
   from repo_security_scanner.models import Dependency, Ecosystem

   @register_parser
   class YourParser(DependencyParser):
       filenames = ["your-lockfile.lock"]
       ecosystem = Ecosystem.YOUR_ECO

       def parse(self, content: str, filename: str) -> list[Dependency]:
           # Parse file content, return list of dependencies
           ...
   ```

3. Import it in `src/repo_security_scanner/parsers/__init__.py`

4. Add the ecosystem mapping in `src/repo_security_scanner/vulndb/osv.py` (`ECOSYSTEM_MAP`)

5. Add tests in `tests/test_parsers.py`

6. Update the README ecosystem table

### Adding a New Vulnerability Source

1. Create `src/repo_security_scanner/vulndb/your_source.py`
2. Implement `VulnDatabase.query_batch()`
3. Wire it up in `src/repo_security_scanner/cli.py`
4. Add tests

### Code Style

- Keep it simple — stdlib over third-party where practical
- Only two runtime dependencies allowed: `requests` and `rich`
- Use type hints
- Follow existing patterns in the codebase

### Running Tests

```bash
# All tests
pytest

# Verbose output
pytest -v

# Single test file
pytest tests/test_parsers.py
```

### Pull Request Process

1. Fork the repo
2. Create a feature branch (`git checkout -b feature/your-feature`)
3. Make your changes
4. Run `pytest` and make sure all tests pass
5. Commit with a clear message
6. Push and open a PR

## Code of Conduct

Be respectful and constructive. We're all here to make dependency security easier for everyone.
