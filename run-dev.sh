#!/usr/bin/env bash
# Quick dev launcher — runs from source, no install needed.
cd "$(dirname "${BASH_SOURCE[0]}")"
PYTHONPATH=src:helpers .venv/bin/python src/app.py
