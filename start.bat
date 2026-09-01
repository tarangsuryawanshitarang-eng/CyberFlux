@echo off
echo ===================================================
echo   Starting CyberFlux - AI Threat Detection System
echo   SIH 26145 Prototype / Demonstration Build
echo ===================================================

echo [1/2] Launching Backend on http://localhost:8000 ...
start "CyberFlux Backend" cmd /k "cd backend && python -m uvicorn app.main:app --reload --port 8000"

timeout /t 2 /nobreak >nul

echo [2/2] Launching Frontend on http://localhost:5173 ...
start "CyberFlux Frontend" cmd /k "cd frontend && npm run dev"

echo ===================================================
echo   CyberFlux is running!
echo   Frontend: http://localhost:5173
echo   Backend API: http://localhost:8000
echo   API Docs: http://localhost:8000/docs
echo ===================================================
