DELETE_ON_ERROR:

env:
	python -m virtualenv env

requirements:
	pip install -r requirements.txt

lint:
	python -m pylint atakama
	black atakama

test:
	PYTHONPATH=. pytest --cov atakama --cov-fail-under=100 -v tests

publish:
	rm -rf dist
	python3 setup.py bdist_wheel
	twine upload dist/*

install-hooks:
	pre-commit install

.PHONY: test requirements lint publish install-hooks
