all:
	@echo "Available targets:"
	@echo
	@echo "make coverage - Run test units and report code coverage"
	@echo "make test     - Run test units"
	@echo "make format   - Format code"

format:
	yapf --style google -i -r .

test:
	python3 tests

coverage:
	coverage run tests
	coverage report
	coverage html
	coverage xml
