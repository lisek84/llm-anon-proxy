"""Launch the proxy:  python -m anonproxy"""
import uvicorn

from .config import config

if __name__ == "__main__":
    uvicorn.run("anonproxy.main:app", host=config.HOST, port=config.PORT, log_level="info")
