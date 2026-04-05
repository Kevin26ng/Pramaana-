"""
Main entry point — starts the FastAPI compliance proxy server.
"""

import uvicorn
from api.proxy import app


if __name__ == "__main__":
    uvicorn.run(
        "api.proxy:app",
        host="0.0.0.0",
        port=8000,
        reload=True,
    )
