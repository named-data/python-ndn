test:
	venv/bin/pytest tests

test-cov:
	venv/bin/pytest tests --cov=src --cov-report term-missing

upload:
	rm -rf dist
	python3 setup.py sdist bdist_wheel
	python3 -m twine upload dist/*

install-edit:
	venv/bin/pip3 install -e .

venv:
	python3.6 -m venv venv	
	./venv/bin/pip3 install pytest pytest-cov

