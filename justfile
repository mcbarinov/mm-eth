version := `python -c 'import tomllib; print(tomllib.load(open("pyproject.toml", "rb"))["project"]["version"])'`


clean:
    rm -rf .pytest_cache .mypy_cache .ruff_cache .coverage dist build *.egg-info

build: clean lint audit test
    python -m build

format:
    ruff check --select I --fix src tests
    ruff format src tests

test:
    coverage run -m pytest -n auto tests

lint: format
    ruff check src tests
    mypy src

audit:
    pip-audit
    bandit -r -c "pyproject.toml" src

publish: build
    git diff-index --quiet HEAD
    twine upload dist/**
    git tag -a 'v{{version}}' -m 'v{{version}}'
    git push origin v{{version}}

pip-upgrade:
    rm -f requirements.txt requirements-dev.txt
    uv pip compile -o requirements.txt pyproject.toml
    uv pip compile -o requirements-dev.txt --extra=dev pyproject.toml
    uv pip sync requirements-dev.txt
    uv pip install -e .

anvil:
    anvil -m "$MNEMONIC"
