#!/usr/bin/env bash
# test_local.sh — Run inference against local Ollama (no HF token needed)
#
# Usage:
#   ./test_local.sh                   # uses qwen2.5:7b (default)
#   ./test_local.sh llama3.2:3b       # use a smaller model

MODEL="${1:-llama3.2:3b}"

# Ollama's OpenAI-compatible endpoint
export API_BASE_URL="http://localhost:11434/v1"
export MODEL_NAME="$MODEL"
export API_KEY="ollama"   # Ollama ignores the key but OpenAI client requires one

echo "==========================================="
echo "  SOC Env — Local Ollama Test"
echo "  Model:    $MODEL_NAME"
echo "  Endpoint: $API_BASE_URL"
echo "  Server:   http://127.0.0.1:8000"
echo "==========================================="

# Check Ollama is running
if ! curl -s http://localhost:11434/api/tags > /dev/null 2>&1; then
    echo "[ERROR] Ollama is not running. Start it with: ollama serve"
    exit 1
fi

# Check model is available
if ! ollama list | grep -q "$MODEL"; then
    echo "[ERROR] Model '$MODEL' not found. Pull it with: ollama pull $MODEL"
    echo "Available models:"
    ollama list
    exit 1
fi

# Check env server is running
if ! curl -s http://127.0.0.1:8000/health > /dev/null 2>&1; then
    echo "[WARN] SOC env server not detected at :8000 — starting it..."
    uv run uvicorn server.app:app --host 0.0.0.0 --port 8000 &
    SERVER_PID=$!
    sleep 3
    echo "[INFO] Server PID: $SERVER_PID"
fi

echo ""
uv run python inference.py

# Cleanup background server if we started it
if [ -n "${SERVER_PID:-}" ]; then
    kill "$SERVER_PID" 2>/dev/null
fi
