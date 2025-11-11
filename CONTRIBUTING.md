# Contributing Guidelines

Thanks for your interest in contributing to this project!

## Getting Started
1. Fork the repository.
2. Clone your fork and create a new feature branch:
   ```bash
   git checkout -b feature/your-feature-name
   ```

3. Make your changes, keeping code readable and well-documented.
4. Run tests before committing:

   ```bash
   pytest
   ```
5. Commit and push your branch:

   ```bash
   git push origin feature/your-feature-name
   ```
6. Open a Pull Request (PR) against the `main` branch.

---

## Reporting Issues

Use the [Issues](../../issues) tab to:

* Report bugs
* Suggest features
* Ask for clarifications

Please include reproducible steps, screenshots, or logs when applicable.

---

## Code Style

* Follow **PEP8** for Python code.
* Use clear variable and function names.
* Document public functions and classes using docstrings.
* Avoid hardcoding sensitive values or credentials.

---

## Testing

All new code should be covered by tests before submitting a PR.

Run all tests:

```bash
pytest --maxfail=1 --disable-warnings -q
```

---

## Pull Request Expectations

* Ensure PRs are **small and focused**.
* Reference the issue number in your PR description.
* PRs are reviewed before merging — please be open to feedback.
