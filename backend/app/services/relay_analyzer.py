import ipaddress
import re
from collections.abc import Iterable

from app.schemas.email import (
    CandidateSourceIP,
    ExtractedIP,
    RelayAnalysis,
    RelayAnalysisMetadata,
    RelayHop,
)

_IP_TOKEN = re.compile(r"[0-9A-Fa-f:.]+")
_HOST_TOKEN = re.compile(
    r"(?i)\b(?:from|by|via|with)\s+((?:localhost)|(?:[A-Za-z0-9]"
    r"[A-Za-z0-9.-]*\.[A-Za-z]{2,}))"
)
_DOCUMENTATION_NETWORKS = (
    ipaddress.ip_network("192.0.2.0/24"),
    ipaddress.ip_network("198.51.100.0/24"),
    ipaddress.ip_network("203.0.113.0/24"),
    ipaddress.ip_network("2001:db8::/32"),
)


def _extract_addresses(header: str) -> list[ipaddress.IPv4Address | ipaddress.IPv6Address]:
    addresses: list[ipaddress.IPv4Address | ipaddress.IPv6Address] = []
    seen: set[str] = set()
    for token in _IP_TOKEN.findall(header):
        try:
            address = ipaddress.ip_address(token)
        except ValueError:
            continue
        normalized = str(address)
        if normalized not in seen:
            addresses.append(address)
            seen.add(normalized)
    return addresses


def _classification(address: ipaddress.IPv4Address | ipaddress.IPv6Address) -> str:
    if any(address in network for network in _DOCUMENTATION_NETWORKS):
        return "documentation_or_test"
    if address.is_loopback:
        return "loopback"
    if address.is_link_local:
        return "link_local"
    if address.is_private:
        return "private"
    if address.is_multicast:
        return "multicast"
    if address.is_unspecified:
        return "unspecified"
    return "public"


def _is_public_source_candidate(
    address: ipaddress.IPv4Address | ipaddress.IPv6Address,
) -> bool:
    return _classification(address) == "public"


def _hostnames(header: str, addresses: Iterable[ipaddress.IPv4Address | ipaddress.IPv6Address]) -> list[str]:
    address_text = {str(address).lower() for address in addresses}
    hostnames: list[str] = []
    for match in _HOST_TOKEN.finditer(header):
        hostname = match.group(1).rstrip(".")
        if hostname.lower() not in address_text and hostname not in hostnames:
            hostnames.append(hostname)
    return hostnames


def analyze_received_headers(received_headers: list[str]) -> RelayAnalysis:
    """Reconstruct Received headers oldest-to-newest.

    SMTP servers prepend their Received header, so parsed headers are normally
    newest-first. Hop numbers retain that input order, while relay_hops reverse
    it to show the message's likely travel path from oldest to newest.
    """
    hops_newest_first: list[RelayHop] = []
    all_ips: list[ExtractedIP] = []

    for input_index, header in enumerate(received_headers, start=1):
        addresses = _extract_addresses(header)
        extracted_ips = [
            ExtractedIP(
                address=str(address),
                version=address.version,
                classification=_classification(address),
                is_public_source_candidate=_is_public_source_candidate(address),
                hop_number=input_index,
            )
            for address in addresses
        ]
        all_ips.extend(extracted_ips)
        hops_newest_first.append(
            RelayHop(
                hop_number=input_index,
                original_header=header,
                hostnames=_hostnames(header, addresses),
                extracted_ips=extracted_ips,
            )
        )

    hops_oldest_first = list(reversed(hops_newest_first))
    public_candidates = [
        extracted_ip for extracted_ip in all_ips if extracted_ip.is_public_source_candidate
    ]
    oldest_public = next(
        (
            extracted_ip
            for hop in hops_oldest_first
            for extracted_ip in hop.extracted_ips
            if extracted_ip.is_public_source_candidate
        ),
        None,
    )

    if oldest_public is not None:
        source = CandidateSourceIP(
            address=oldest_public.address,
            confidence="moderate",
            reason=(
                "Oldest public IP found in the reconstructed relay path; "
                "this is probable source infrastructure, not a definitive attacker IP."
            ),
        )
    elif public_candidates:
        source = CandidateSourceIP(
            address=public_candidates[0].address,
            confidence="low",
            reason=(
                "A public relay IP was found, but no older public hop established "
                "a stronger source ordering; this is probable source infrastructure."
            ),
        )
    else:
        source = CandidateSourceIP(
            address=None,
            confidence="none",
            reason=(
                "No public source candidate remained after excluding private, "
                "loopback, link-local, and documentation/test ranges."
            ),
        )

    return RelayAnalysis(
        relay_hops=hops_oldest_first,
        extracted_ips=all_ips,
        probable_source_infrastructure=source,
        metadata=RelayAnalysisMetadata(
            received_header_count=len(received_headers),
            input_header_order="newest_first",
            reconstructed_order="oldest_to_newest",
            source_selection_scope="public IPs only; reserved and internal ranges excluded",
        ),
    )
