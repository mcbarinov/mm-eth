set dotenv-load
version := `uv run python -c 'import tomllib; print(tomllib.load(open("pyproject.toml", "rb"))["project"]["version"])'`


clean:
    rm -rf .pytest_cache .mypy_cache .ruff_cache .coverage dist build src/*.egg-info

build: clean lint audit test
    uv build

format:
    uv run ruff check --select I --fix src tests
    uv run ruff format src tests

test:
    uv run pytest -n auto tests

lint: format
    uv run ruff check src tests
    uv run mypy src

audit:
    uv run pip-audit
    uv run bandit -r -c "pyproject.toml" src

publish: build
    git diff-index --quiet HEAD
    uvx twine upload dist/**
    git tag -a 'v{{version}}' -m 'v{{version}}'
    git push origin v{{version}}

sync:
    uv sync

anvil:
    anvil -m "$MNEMONIC"
