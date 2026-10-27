.PHONY: test smoke doctor scan verify-source source-audit rule-fixtures coverage release release-full manifest
PYTHON ?= python3

test:
	$(PYTHON) -m unittest discover -s tests -q

smoke:
	$(PYTHON) -m compileall -q falsicore falsicore.py tools

scan:
	./run.sh

doctor:
	$(PYTHON) -I falsicore.py doctor

verify-source:
	sha256sum -c SOURCE_MANIFEST.sha256
	$(PYTHON) tools/build_release.py --check-manifest

manifest:
	$(PYTHON) tools/build_release.py --write-manifest

source-audit:
	$(PYTHON) tools/code_audit.py . --fail-on high

rule-fixtures:
	$(PYTHON) -m tools.evaluate_rules

coverage:
	$(PYTHON) -m coverage run --branch --source=falsicore -m unittest discover -s tests -q
	$(PYTHON) -m coverage report -m --fail-under=88

release:
	@out=$$(mktemp -d); $(PYTHON) tools/build_app.py "$$out/falsicore.pyz"; echo "RELEASE: $$out/falsicore.pyz"

release-full:
	@out=$$(mktemp -d); $(PYTHON) tools/build_full.py "$$out"; echo "FULL RELEASE: $$out"
