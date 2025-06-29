from rich.console import Console
from rich.logging import RichHandler
import logging

def get_logger(verbosity: int = 0) -> logging.Logger:
    level = logging.WARNING - min(verbosity, 2) * 10
    handler = RichHandler(console=Console(stderr=True), show_time=False, show_level=True)
    logging.basicConfig(level=level, format="%(message)s", handlers=[handler])
    return logging.getLogger("fp")
