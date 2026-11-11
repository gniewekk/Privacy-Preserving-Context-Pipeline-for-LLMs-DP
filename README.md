# Privacy-Preserving Context Pipeline for LLMs

University Design Patterns & Security project: a Python pipeline that detects PII/PHI in
prompts, anonymizes or pseudonymizes it (masking, reversible AES-256-GCM tokenization,
k-anonymity generalization) before the context reaches an external LLM, enforces EU data
residency, and restores authorised values in the response. The architecture is built on
Pipes & Filters, Strategy, Builder, Protection Proxy and Memento — see
[`ARCHITECTURE.md`](ARCHITECTURE.md), [`AGENTS.md`](AGENTS.md) and [`docs/adr/`](docs/adr/).

## Installation

Requires Python 3.12+.

```bash
# pip
python3.12 -m venv .venv
source .venv/bin/activate
pip install -e ".[dev]"

# or uv
uv sync --extra dev
```

## Quality gates

All five must pass before opening a PR (the same steps run in
[`.github/workflows/ci-security.yml`](.github/workflows/ci-security.yml)):

```bash
ruff check src/ tests/
mypy --strict src/
pytest -v
bandit -r src/ -ll -ii
pip-audit
```

With uv, prefix each command with `uv run`.
