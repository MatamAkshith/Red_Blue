#!/usr/bin/env bash
set -e

# BLACKBOX P3 Live Target Agent Master Demo Script

PYTHON_ENV="./venv/bin/python"
if [ ! -f "$PYTHON_ENV" ]; then
    PYTHON_ENV="python3"
fi

SCENARIO="${1:-malicious}"
RESET_FLAG=""

if [ "$1" == "--reset" ] || [ "$2" == "--reset" ]; then
    RESET_FLAG="--reset"
fi

echo "=== Starting BLACKBOX Live Target Demonstration (P3) ==="
PYTHONPATH=. $PYTHON_ENV -m backend.app.target.demo_runner --scenario "$SCENARIO" $RESET_FLAG
