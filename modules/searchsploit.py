#!/usr/bin/env python3
"""
Project: ScAnRoIdS Red Team Orchestrator
Module: modules/searchsploit.py
Purpose: Record version-based exploit references without claiming verified vulnerability.
"""

from modules.tools import artifact_output, execute, services


def run_search(ctx, service_string, ip="Unknown"):
    query = service_string.strip()
    if not query or query.lower() == "unknown":
        return None
    result = execute(ctx, ["searchsploit", "--disable-colour", *query.split()], timeout=60)
    return artifact_output(
        ctx,
        result,
        "searchsploit",
        f"HOST: {ip}\nSEARCH: {query}\nMatches are references, not confirmed vulnerabilities.\n\n",
    )


def run_searchsploit(ctx):
    queries = {}
    for row in services(ctx):
        query = " ".join(filter(None, (row.get("product"), row.get("version")))).strip()
        if query:
            queries.setdefault(query, set()).add(f"{row['ip']}:{row['port']}/{row['protocol']}")
    for query, hosts in sorted(queries.items()):
        run_search(ctx, query, ", ".join(sorted(hosts)))


"""
INPUT: Service product/version evidence and originating targets.
OUTPUT: SearchSploit reference reports and per-query execution history.
"""
