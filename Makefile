.PHONY: install samples rules analyze report test lint format app clean

install:
	pip install -r requirements-dev.txt

samples:
	python scripts/generate_samples.py

rules:
	triagedesk rules

analyze:
	triagedesk analyze data/samples/auth.log data/samples/access.log --offline

report:
	triagedesk analyze data/samples/auth.log data/samples/access.log --offline \
		--report reports/sample_report.md --json reports/sample_report.json

test:
	pytest

lint:
	ruff check src scripts tests app
	ruff format --check src scripts tests app

format:
	ruff format src scripts tests app

app:
	streamlit run app/streamlit_app.py

clean:
	rm -rf reports .pytest_cache .ruff_cache build dist src/*.egg-info
