# Reproduce everything from a clean checkout. On Windows without make, use ./run.ps1 <target>.
PY ?= python
CONFIG ?= config/default.toml
DAYS ?= 15

.PHONY: setup synthetic lanl ingest features pipeline evaluate explain test clean

setup:
	$(PY) -m pip install -e ".[dev,models]"

synthetic:
	$(PY) -m threatdet.data.synthetic --config $(CONFIG)

lanl:  ## streams only days < DAYS of auth.txt.gz; review the LANL terms first
	$(PY) -m threatdet.data.download_lanl --config $(CONFIG) --days $(DAYS)

ingest:
	$(PY) -m threatdet.pipeline ingest --config $(CONFIG)

features:
	$(PY) -m threatdet.pipeline features --config $(CONFIG)

pipeline: synthetic
	$(PY) -m threatdet.pipeline all --config $(CONFIG)

evaluate:  ## fit on days < train_end_day, score the rest, write reports/metrics_<source>.*
	$(PY) -m threatdet.evaluate --config $(CONFIG)

explain:  ## SHAP evidence packs for the top alerts (triage/explain.py)
	$(PY) -m triage.explain --config $(CONFIG)

test:
	$(PY) -m pytest

clean:
	$(PY) -c "import pathlib; [p.unlink() for p in pathlib.Path('data').glob('*.duckdb*')]"
