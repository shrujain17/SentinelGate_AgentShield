#!/usr/bin/env bash
# ==============================================================================
# AgentShield - Backend & Security Gateway Startup Script (Bash)
# ==============================================================================
set -e

PROJECT_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
cd "$PROJECT_ROOT"

echo "========================================================================"
echo "🛡️  AGENTSHIELD - STARTING FASTAPI BACKEND & SECURITY GATEWAY"
echo "========================================================================"

# Check for .env file
if [ ! -f "$PROJECT_ROOT/.env" ]; then
    if [ -f "$PROJECT_ROOT/.env.example" ]; then
        echo "⚠️  Creating default .env from .env.example..."
        cp "$PROJECT_ROOT/.env.example" "$PROJECT_ROOT/.env"
    fi
fi

# Locate Python
if [ -f "$PROJECT_ROOT/.venv/bin/python" ]; then
    PYTHON_EXE="$PROJECT_ROOT/.venv/bin/python"
    echo "✅ Using local virtual environment: $PYTHON_EXE"
elif command -v python3 &>/dev/null; then
    PYTHON_EXE="python3"
    echo "⚠️  Using system python3: $(command -v python3)"
else
    echo "❌ Python 3 is not installed or not in PATH."
    exit 1
fi

# Check dependencies
$PYTHON_EXE -c "import fastapi, uvicorn, sqlalchemy, pydantic" 2>/dev/null || {
    echo "📦 Installing requirements..."
    $PYTHON_EXE -m pip install -r requirements.txt
}

echo ""
echo "🚀 Launching AgentShield on http://127.0.0.1:8000..."
echo "   - React SOC Dashboard: http://127.0.0.1:8000/"
echo "   - Interactive Swagger API: http://127.0.0.1:8000/docs"
echo "   - Health Check: http://127.0.0.1:8000/health"
echo ""
echo "Press Ctrl+C to stop the backend server."
echo "------------------------------------------------------------------------"

exec $PYTHON_EXE -m uvicorn main:app --host 127.0.0.1 --port 8000 --reload
