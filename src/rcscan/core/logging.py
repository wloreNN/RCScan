"""Application logging configuration."""

import logging


def configure_logging(verbose: bool = False) -> None:
    """Configure concise timestamped stderr logging."""
    level = logging.DEBUG if verbose else logging.WARNING
    handler = logging.StreamHandler()
    handler.setFormatter(
        logging.Formatter(
            fmt="%(asctime)s %(levelname)s %(name)s: %(message)s",
            datefmt="%Y-%m-%dT%H:%M:%S",
        )
    )
    root = logging.getLogger("rcscan")
    root.handlers.clear()
    root.addHandler(handler)
    root.setLevel(level)
    root.propagate = False
