"""
Lightweight bridge to reuse the BYOVD API scanner from the v1 codebase.

This module tries to import ``find_dangerous_apis`` from the original iKARMA
utilities (kept in the sibling ``iKARMA`` directory). If the modules are not
present, the bridge simply returns ``None`` so the caller can skip BYOVD
analysis without failing the pipeline.
"""

import sys
import logging
from functools import lru_cache
from pathlib import Path
from typing import Callable, List, Dict, Any, Optional

logger = logging.getLogger(__name__)


@lru_cache(maxsize=1)
def load_byovd_api_scanner() -> Optional[Callable[[List[str]], List[Dict[str, Any]]]]:
    """
    Attempt to import the legacy BYOVD API scanner.

    Returns:
        Callable if available, otherwise None.
    """
    # Candidate paths where the legacy utilities may live relative to v2 repo root
    this_dir = Path(__file__).resolve().parent
    repo_root = this_dir.parent
    candidates = [
        repo_root / "utils",  # legacy utils copied into v2 root
    ]

    for path in candidates:
        if path.is_dir() and str(path) not in sys.path:
            sys.path.insert(0, str(path))

    try:
        from utils.api_scanner import find_dangerous_apis  # type: ignore

        logger.info("BYOVD API scanner loaded")
        return find_dangerous_apis  # noqa: F401
    except Exception as e:  # pragma: no cover - defensive import
        logger.warning(f"BYOVD API scanner not available: {e}")
        return None


def scan_dangerous_apis(disassembly: List[str]) -> List[Dict[str, Any]]:
    """
    Run BYOVD API scanner against a list of disassembly strings.

    Args:
        disassembly: List of disassembly lines (address + mnemonic/op_str)

    Returns:
        List of finding dictionaries (empty if scanner not available).
    """
    scanner = load_byovd_api_scanner()
    if not scanner:
        return []

    try:
        return scanner(disassembly)
    except Exception as e:  # pragma: no cover - defensive runtime guard
        logger.debug(f"BYOVD API scanner execution failed: {e}")
        return []
