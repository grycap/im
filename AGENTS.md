# Repository Guidelines

## Purpose of This File
- This file defines mandatory rules for AI agents and humans using AI while
  working in this repository.
- Follow these rules unless a repository maintainer explicitly overrides them.

## Agent Operating Principles
- You MUST preserve existing behavior unless a change is explicitly requested.
- You MUST keep changes minimal and targeted to the task.
- You SHOULD prefer small, understandable edits over broad refactors.
- You MUST keep the codebase maintainable and readable.

## Allowed and Forbidden Actions
- You MAY add or edit files needed to complete the requested task.
- You MAY run tests and formatting/security checks relevant to changed code.
- You MUST NOT delete files, change licenses, or modify CI/CD workflows without
  explicit approval.
- You MUST NOT introduce new dependencies without explicit approval.
- Preserve existing local and untracked files; do not overwrite user data or
  generated state such as local databases.

## Code Quality Standards
- New code MUST be written in Python 3 and follow the project's PEP 8 style.
- Keep lines at or below 120 characters, consistent with `CONTRIBUTING.md` and
  `tox.ini`.
- Public functions and new functionality SHOULD include clear docstrings using
  the project's Sphinx-style documentation convention.
- Prefer existing IM abstractions and connector patterns over introducing
  parallel implementations.
- Keep compatibility with the Python versions supported by the project; consult
  `pyproject.toml` and CI configuration before using newer language features.

## Change Scope & Discipline
- Stay within the scope of the request; avoid opportunistic cleanup.
- Do not alter public APIs, RADL/TOSCA behavior, configuration formats, or
  persistence semantics unless explicitly requested.
- Before changing interfaces, configuration, or deployment behavior, identify
  affected consumers and documentation and ask if the requested behavior is
  ambiguous.
- Do not modify the existing virtual environments or install, update, or
  rebuild dependencies as part of repository work unless explicitly approved.

## Testing & Validation
- The project uses `tox`; its environments and commands are defined in `tox.ini`.
- Run relevant unit tests for Python changes. The project's unit-test command is:
  `python -m unittest discover -v -s test/unit -p '*.py'`.
- Run the style check when relevant: `tox -e style` (or the configured
  `pycodestyle` command from `tox.ini` using an already available environment).
- Run `tox -e bandit` for relevant security-sensitive changes when feasible.
- Do not let test runs overwrite existing user data or local databases; inspect
  test configuration and fixtures first and isolate mutable state when supported.
- If tests are not run, state why and what was skipped. If tests fail, report the
  failures without masking them.
- Documentation-only changes may skip tests; state this explicitly.

## Security & Safety Rules
- MUST NOT add secrets, credentials, tokens, private keys, or sensitive
  infrastructure details to the repository.
- Configuration examples MUST use placeholders for credentials.
- Do not weaken authentication, authorization, TLS, or certificate validation
  defaults.
- Treat cloud credentials and provider configuration as sensitive; do not print
  or commit them while debugging.
- Dependency changes require explicit maintainer approval and a justification
  of their impact.

## Documentation Responsibilities
- Update the relevant documentation under `doc/` and/or `README.md` when public
  interfaces, configuration, behavior, or deployment instructions change.
- Keep documentation concise and aligned with behavior verified in the code.
- Follow the documentation conventions used by the existing Sphinx project.

## Project Structure & Validation References
- Core implementation: `IM/`.
- Cloud and infrastructure connectors: `IM/connectors/`.
- REST API: `IM/rest/` and `IM/rest/routers/`.
- TOSCA support: `IM/tosca/`.
- Contextualization: `contextualization/`.
- Tests: `test/unit/`, `test/integration/`.
- Examples: `examples/`.
- Project configuration and test commands: `pyproject.toml`, `tox.ini`, and
  `.github/workflows/main.yaml`.
- Do not modify CI workflows unless explicitly approved.

## Commit & PR Expectations (if applicable)
- Follow `CONTRIBUTING.md` for contribution and pull-request requirements.
- Commits SHOULD use short, imperative messages.
- Pull requests SHOULD include a clear description and relevant tests.
- Update documentation and version references when required by
  `CONTRIBUTING.md`.

## When to Ask for Clarification
- Requirements conflict with this file or are ambiguous.
- The change requires new dependencies, CI/CD edits, or license changes.
- The change affects external interfaces, configuration, security, or
  deployment behavior and the expected compatibility is unclear.
- Tests cannot be run safely or consistently fail.
