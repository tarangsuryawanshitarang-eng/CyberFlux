#!/bin/bash
echo "==================================================="
echo "  Starting CyberFlux - AI Threat Detection System"
echo "  SIH 26145 Prototype / Demonstration Build"
echo "==================================================="

echo "[1/2] Starting Backend on http://localhost:8000 ..."
(cd backend && python -m uvicorn app.main:app --reload --port 8000) &
BACKEND_PID=$!

sleep 2

echo "[2/2] Starting Frontend on http://localhost:5173 ..."
(cd frontend && npm run dev) &
FRONTEND_PID=$!

echo "==================================================="
echo "  CyberFlux is running!"
echo "  Frontend: http://localhost:5173"
echo "  Backend API: http://localhost:8000"
echo "  API Docs: http://localhost:8000/docs"
echo "==================================================="

trap "kill $BACKEND_PID $FRONTEND_PID" EXIT
wait
