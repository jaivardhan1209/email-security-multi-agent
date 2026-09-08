.PHONY: install test lint evaluate demo samples ui doctor graph docker clean

VENV ?= .venv
PY   := $(VENV)/bin/python

install:
	python3 -m venv $(VENV)
	$(PY) -m pip install --upgrade pip
	$(PY) -m pip install -r requirements.txt

test:
	$(PY) -m pytest

lint:
	$(PY) -m ruff check email_security tests app.py

doctor:
	$(PY) app.py doctor

graph:
	$(PY) app.py graph

demo:
	$(PY) app.py demo

ui:
	$(PY) server.py            # http://127.0.0.1:8800

samples:
	@for f in data/samples/unseen/*.json; do $(PY) app.py analyze $$f; done

evaluate:
	$(PY) -m email_security.evaluation.evaluate --json results.json

docker:
	docker build -t email-security-poc .

clean:
	rm -rf $(VENV) .pytest_cache .ruff_cache results*.json
	find . -name __pycache__ -type d -prune -exec rm -rf {} +
