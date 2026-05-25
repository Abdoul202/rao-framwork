.PHONY: install install-dev test lint deps-update clean

# ── Installation ──────────────────────────────────────────────────────────────
install:
	pip install -r requirements.txt
	pip install -e .

install-dev:
	pip install -r requirements.txt -r requirements-dev.txt
	pip install -e .

# ── Tests ─────────────────────────────────────────────────────────────────────
test:
	pytest tests/ -v --tb=short

test-ci:
	pytest tests/ -v --tb=short --no-header -q

# ── Lint ──────────────────────────────────────────────────────────────────────
lint:
	ruff check rao/ tests/

lint-fix:
	ruff check rao/ tests/ --fix

# ── Dependency management ─────────────────────────────────────────────────────
# Épingler les versions exactes depuis les fichiers .in
deps-compile:
	pip-compile requirements.in -o requirements.txt
	pip-compile requirements-dev.in -o requirements-dev.txt

# Mettre à jour vers les dernières versions compatibles et réépingler
deps-update:
	pip-compile requirements.in -o requirements.txt --upgrade
	pip-compile requirements-dev.in -o requirements-dev.txt --upgrade

# ── Développement ─────────────────────────────────────────────────────────────
dev:
	docker compose -f docker-compose.dev.yml up -d
	@echo "Neo4j ready at http://localhost:7474"

dev-down:
	docker compose -f docker-compose.dev.yml down

# ── Nettoyage ─────────────────────────────────────────────────────────────────
clean:
	find . -type d -name __pycache__ -exec rm -rf {} + 2>/dev/null || true
	find . -type f -name "*.pyc" -delete 2>/dev/null || true
	rm -rf .pytest_cache dist build *.egg-info
