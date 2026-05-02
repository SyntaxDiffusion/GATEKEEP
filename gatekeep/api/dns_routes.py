"""
DNS integrity check API routes for GATEKEEP.

Provides an endpoint to run an on-demand DNS security check
independent of a full network scan.
"""

from __future__ import annotations

from typing import Any

from fastapi import APIRouter, Depends

from gatekeep.api.deps import get_config
from gatekeep.config import GatekeepConfig
from gatekeep.logging_config import get_logger
from gatekeep.schemas import ApiResponse

logger = get_logger(__name__)

router = APIRouter(prefix="/dns", tags=["dns"])


@router.get("/check", response_model=ApiResponse[dict[str, Any]])
async def run_dns_check(
    config: GatekeepConfig = Depends(get_config),
) -> ApiResponse[dict[str, Any]]:
    """
    Run a DNS integrity check now.

    Validates the system's configured DNS resolvers against trusted
    resolver lists and known APT28 malicious infrastructure, then
    performs comparative resolution checks on test domains and
    FrostArmada-targeted Microsoft authentication endpoints.

    This check runs independently of a full scan and does not persist
    results to the database.
    """
    from gatekeep.engines.dns_checker import DNSChecker

    checker = DNSChecker(config.dns)
    results = await checker.full_check()

    # Build response
    is_hijacked = any(
        r.status == "hijacked" for r in results
    )
    any_malicious = any(r.is_malicious for r in results)

    resolvers: list[dict[str, Any]] = []
    for r in results:
        resolution_details = [
            {
                "domain": rr.domain,
                "resolved_ips": rr.resolved_ips,
                "control_ips": rr.control_ips,
                "matches": rr.matches,
                "is_hijacked": rr.is_hijacked,
                "hijack_type": rr.hijack_type,
                "details": rr.details,
                "error": rr.error,
            }
            for rr in r.resolution_results
        ]
        resolvers.append({
            "resolver_ip": r.resolver_ip,
            "resolver_name": r.resolver_name,
            "is_trusted": r.is_trusted,
            "is_malicious": r.is_malicious,
            "malicious_campaign": r.malicious_campaign,
            "status": r.status.value if hasattr(r.status, "value") else str(r.status),
            "details": r.details,
            "resolution_results": resolution_details,
        })

    hijacked_count = sum(
        1
        for r in results
        for rr in r.resolution_results
        if rr.is_hijacked
    )

    response_data = {
        "is_hijacked": is_hijacked,
        "is_malicious_resolver": any_malicious,
        "resolver_count": len(resolvers),
        "hijacked_domain_count": hijacked_count,
        "resolvers": resolvers,
    }

    return ApiResponse[dict[str, Any]](
        status="success",
        data=response_data,
    )
