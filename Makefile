test:
	venv/bin/pytest

test-cov:
	venv/bin/pytest --cov=src --cov-report term-missing

install-edit:
	venv/bin/pip3 install -e .

venv:
	python3.6 -m venv venv	
	./venv/bin/pip3 install pytest pytest-cov

