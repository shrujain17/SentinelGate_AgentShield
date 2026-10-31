#!/usr/bin/env bash
# ==============================================================================
# AgentShield - Frontend Development Server Startup Script (Bash)
# ==============================================================================
set -e

PROJECT_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
FRONTEND_DIR="$PROJECT_ROOT/frontend"

cd "$FRONTEND_DIR"

if ! command -v npm &>/dev/null; then
    echo "❌ Node.js / npm not found in PATH."
    echo "💡 Note: The production React dashboard is already pre-compiled and served"
    echo "   by FastAPI at http://127.0.0.1:8000/. Just run ./start_backend.sh!"
    exit 1
fi

if [ ! -d "$FRONTEND_DIR/node_modules" ]; then
    echo "📦 Installing npm dependencies..."
    npm install
fi

echo "🚀 Starting Vite dev server on http://127.0.0.1:5173..."
npm run dev
