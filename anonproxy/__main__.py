"""Launch the proxy:  python -m anonproxy"""
import logging

import uvicorn

from . import tls
from .config import config

if __name__ == "__main__":
    cert, key = tls.resolve()
    scheme = "https" if cert else "http"
    logging.getLogger("anonproxy").info(
        "listening on %s://%s:%s%s", scheme, config.HOST, config.PORT,
        "" if scheme == "https" or config.HOST == "127.0.0.1"
        else "  (plain HTTP — do not expose beyond loopback)")
    uvicorn.run("anonproxy.main:app", host=config.HOST, port=config.PORT,
                log_level="info", ssl_certfile=cert, ssl_keyfile=key)
