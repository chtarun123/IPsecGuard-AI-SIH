"""
IPsecGuard AI - One-Click Dual Server Launcher
Starts both the FastAPI backend and Vite frontend simultaneously,
and automatically opens the dashboard in your default browser.
"""

import os
import sys
import time
import subprocess
import webbrowser

def main():
    root_dir = os.path.abspath(os.path.dirname(__file__))
    backend_dir = os.path.join(root_dir, "backend")
    frontend_dir = os.path.join(root_dir, "frontend")

    print("=" * 60)
    print("      Launching IPsecGuard AI (Frontend + Backend)       ")
    print("=" * 60)

    # 1. Start FastAPI Backend (Port 8000)
    print("[1/3] Starting FastAPI Backend on http://localhost:8000...")
    backend_proc = subprocess.Popen(
        [sys.executable, "-m", "uvicorn", "main:app", "--reload", "--port", "8000"],
        cwd=backend_dir
    )

    # 2. Start Vite React Frontend (Port 5173)
    npm_cmd = "npm.cmd" if os.name == "nt" else "npm"
    print("[2/3] Starting React Frontend on http://localhost:5173...")
    frontend_proc = subprocess.Popen(
        [npm_cmd, "run", "dev"],
        cwd=frontend_dir
    )

    # 3. Wait briefly and open browser
    time.sleep(3)
    print("[3/3] Opening dashboard in browser: http://localhost:5173")
    webbrowser.open("http://localhost:5173")

    print("\n" + "=" * 60)
    print(" [✓] BOTH SERVERS ARE NOW RUNNING SIMULTANEOUSLY! ")
    print("     - Frontend: http://localhost:5173")
    print("     - Backend:  http://localhost:8000")
    print("     - Press Ctrl + C in this window to stop both.")
    print("=" * 60 + "\n")

    try:
        while True:
            time.sleep(1)
    except KeyboardInterrupt:
        print("\nShutting down both servers...")
        backend_proc.terminate()
        frontend_proc.terminate()
        print("[✓] Both servers stopped cleanly.")

if __name__ == "__main__":
    main()
