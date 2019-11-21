test:
	venv/bin/pytest tests

test-cov:
	venv/bin/pytest tests --cov=src --cov-report term-missing

upload:
	rm -rf dist
	python3 setup.py sdist bdist_wheel
	python3 -m twine upload dist/*

lint:
	# exit-zero treats all errors as warnings. The GitHub editor is 127 chars wide
	flake8 src --exclude=src/ndn/contrib --count --ignore=F403,F405,W503,E226 \
		--exit-zero --max-complexity=20 --max-line-length=120 --statistics
	flake8 tests --count --ignore=F403,F405,W503,E226,E222,W504 \
		--exit-zero --max-complexity=50 --max-line-length=120 --statistics
