#!/usr/bin/env bash
set -e

cd "$(dirname "$0")"

echo ""
echo "=========================================="
echo " AI Code Scanner - Starting..."
echo "=========================================="
echo ""

docker compose up -d

echo ""
echo " Waiting for services to be ready..."

until curl -sf http://localhost:8000/health > /dev/null 2>&1; do
  sleep 3
done

echo ""
echo "=========================================="
echo ""
echo "  AI Code Scanner is ready!"
echo ""
echo "  http://localhost:8000"
echo ""
echo "  To view logs:  docker compose logs -f"
echo "  To stop:       docker compose down"
echo ""
echo "=========================================="
echo ""

# Open browser (Mac and Linux)
if command -v open &> /dev/null; then
  open http://localhost:8000
elif command -v xdg-open &> /dev/null; then
  xdg-open http://localhost:8000
fi
