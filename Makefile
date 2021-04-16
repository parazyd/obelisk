all:
	@echo "Available targets"
	@echo "make format - Format code"
	@echo "make test - Run test units"
	@echo "make coverage - Run test units and report code coverage"

format:
	python3 ./res/format_code.py

test:
	python3 ./tests/test_electrum_protocol.py

coverage:
	coverage run tests
	coverage report
