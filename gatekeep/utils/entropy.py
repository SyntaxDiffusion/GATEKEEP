"""
Shannon entropy calculator for DNS tunneling detection.

Provides functions to compute the information entropy of arbitrary
strings and to flag DNS queries whose statistical properties suggest
data exfiltration or command-and-control tunneling.
"""

from __future__ import annotations

import math
from collections import Counter


def shannon_entropy(data: str) -> float:
    """
    Calculate the Shannon entropy of a string.

    Shannon entropy measures the average information content per symbol.
    Uniform random data of base-N alphabet yields log2(N) bits.  For
    printable ASCII DNS labels, normal domains score 2.5-3.5 while
    encoded tunneling payloads typically exceed 4.0.

    Args:
        data: The input string to analyze.

    Returns:
        Entropy value in bits.  Returns 0.0 for empty strings.
    """
    if not data:
        return 0.0

    length = len(data)
    counts = Counter(data)
    entropy = 0.0

    for count in counts.values():
        probability = count / length
        if probability > 0:
            entropy -= probability * math.log2(probability)

    return entropy


def is_suspicious_dns_query(
    query: str,
    entropy_threshold: float = 4.5,
    min_length: int = 50,
) -> tuple[bool, float]:
    """
    Check if a DNS query name exhibits characteristics of tunneling.

    DNS tunneling encodes arbitrary data into subdomain labels, producing
    unusually long hostnames with high character entropy.  This function
    applies both a length and an entropy threshold.

    Args:
        query: The fully-qualified domain name to evaluate.
        entropy_threshold: Minimum Shannon entropy to flag (default 4.5).
        min_length: Minimum query length to flag (default 50 chars).

    Returns:
        A tuple of (is_suspicious, entropy_value).
    """
    if not query:
        return False, 0.0

    # Strip trailing dot if present (FQDN notation)
    clean_query = query.rstrip(".")

    entropy = shannon_entropy(clean_query)

    is_suspicious = entropy > entropy_threshold and len(clean_query) > min_length

    return is_suspicious, entropy
