.DEFAULT_GOAL := build
.PHONY: build

SCRIPT_NAME = wg-interactive


build:
		pipenv run pyinstaller --clean --onefile ${SCRIPT_NAME}.py

init:
		mkdir -pv .venv
		pipenv --three
		pipenv install --dev

clean:
		rm -rvf __pycache__ build dist *.spec

clean-venv:
		rm -rvf .venv

install:
		cp dist/${SCRIPT_NAME} /usr/bin/${SCRIPT_NAME}