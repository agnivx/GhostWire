"""
run.py - Single command application launcher
Starts the FastAPI backend and serves the WebCrypto E2EE Chat UI
"""

import sys
import uvicorn


def main():
    print("=" * 60)
    print("  GHOSTWIRE - ENCRYPTED P2P MESSAGING PLATFORM")
    print("  - Web Application:   http://localhost:8000")
    print("  - Moderator Console: http://localhost:8000/moderator")
    print("  - E2EE Protocol:     WebCrypto ECDH + AES-256-GCM")
    print("  Press Ctrl+C to stop the server.")
    print("=" * 60 + "\n")

    uvicorn.run(
        "server:app",
        host="0.0.0.0",
        port=8000,
        reload=True,
        log_level="info",
    )


if __name__ == "__main__":
    main()
