PROJECT 	:= acme_powerdns
GIT_HUB 	:= https://github.com/adfinis-sygroup/acme-powerdns
DOCKER_DIR  := .testdata
IMAGE_NAME  := acme-powerdns
DEFAULT_CMD := .testdata/run.sh

include pyproject/Makefile
include pyproject/docker.mk

# overwrite TESTDIR
TESTDIR := .

# overwrite pytest
pytest: .requirements.txt .deps/pytest  .deps/coverage .deps/pytest_cov
	rm -f *.so *.dylib
	pip install --upgrade -r .requirements.txt -e .
	py.test --cov-report term-missing --cov=$(PROJECT) --no-cov-on-fail $(TESTDIR)
