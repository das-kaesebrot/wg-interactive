.DEFAULT_GOAL := build

SCRIPT_NAME = wg-interactive


build:
		mkdir -pv .venv
		pipenv --three
		pipenv install --dev
		pipenv run pyinstaller --clean --onefile ${SCRIPT_NAME}.py

clean:
		rm -rvf __pycache__ build dist *.spec

clean-venv:
		rm -rvf .venv

install:
		cp dist/${SCRIPT_NAME} /usr/bin/${SCRIPT_NAME}