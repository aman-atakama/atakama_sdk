DELETE_ON_ERROR:

env:
	python -m virtualenv env

requirements:
	# use isolated so devs don't accidentally check in odd deps
	pip install --isolated -r requirements.txt

lint:
	python -m pylint atakama
	python -m pre_commit run insert-license --all-files
	python -m pre_commit run black --all-files

test:
	PYTHONPATH=. python -mpytest --cov atakama -v tests

publish:
	rm -rf dist
	python3 setup.py bdist_wheel
	twine upload dist/*

install-hooks:
	python -m pre_commit install

docs:
	python -mdocmd --out docs atakama --src=https://github.com/AtakamaLLC/atakama_sdk/blob/master/atakama

.PHONY: test requirements lint publish install-hooks docs
