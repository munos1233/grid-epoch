PY := .venv/bin/python

.PHONY: test demo bench console split scenes

console:
	$(PY) -m grid_epoch.console

split:
	$(PY) -m grid_epoch.split_demo

test:
	$(PY) -m unittest tests.test_grid_epoch -v

demo:
	$(PY) -m grid_epoch.demo

scenes:
	$(PY) -m grid_epoch.scenes run

bench:
	$(PY) bench/bench_scale.py
