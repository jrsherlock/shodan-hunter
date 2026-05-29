"""Entrypoint. `python run.py` boots the team UI on the configured host:port."""

import uvicorn

from hunter import config


def main() -> None:
    uvicorn.run(
        "hunter.app:app",
        host=config.BIND_HOST,
        port=config.BIND_PORT,
        reload=False,
        log_level="info",
    )


if __name__ == "__main__":
    main()
