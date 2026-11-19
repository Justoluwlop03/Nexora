from __future__ import annotations

import logging

from .api import serve
from .config import Config


def main() -> None:
    logging.basicConfig(
        level=logging.INFO,
        format="%(asctime)s %(levelname)s %(name)s %(message)s",
    )
    serve(Config.from_environment())


if __name__ == "__main__":
    main()
