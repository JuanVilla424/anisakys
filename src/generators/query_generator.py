"""
Query Generator Module

Generates search query combinations from keywords and domains.

EPIC-006: Main.py Modularization (STORY-006.2)
"""

import logging
from typing import List
from itertools import permutations

logger = logging.getLogger(__name__)


def generate_queries_file(keywords: List[str], domains: List[str], output_file: str) -> int:
    """
    Generate a query file with all keyword/domain combinations.

    Args:
        keywords: List of keywords to permute
        domains: List of domain extensions
        output_file: Path to output file

    Returns:
        int: Total number of queries generated
    """
    total = 0
    with open(output_file, "w") as f:
        for i in range(1, len(keywords) + 1):
            for p in permutations(keywords, i):
                for q in ["-".join(p), "".join(p)]:
                    for d in domains:
                        f.write(f"{q}{d}\n")
                        total += 1
    logger.info(f"📄 Generated full query list with {total} lines.")
    return total
