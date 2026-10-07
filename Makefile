PY := .venv/bin/python

.PHONY: test demo bench console split

console:
	$(PY) -m grid_epoch.console

split:
	$(PY) -m grid_epoch.split_demo

test:
	$(PY) -m unittest tests.test_grid_epoch -v

demo:
	$(PY) -m grid_epoch.demo

bench:
	$(PY) bench/bench_scale.py
