# This script acts as a connector between OpenCTI and Wazuh, providing
# necessary bidirectionality in order for use in a real-world SOC environment.
# It enriches OpenCTI entities with matching Wazuh alert data, then writes back
# a ranked analyst summary, relevant linked notes, and sightings when applicable.
# It is built to give SOC teams something usable during the process of triage
# by filtering all low-value results and surfacing top agents and rules in a summary.

# Ryan Boulrice - Netizen Corporation
# 3/31/2026

import time
import os
import traceback
import ipaddress
import json
from collections import Counter
from datetime import datetime, timezone
from typing import Any
from urllib.parse import quote
import requests
from requests.auth import HTTPBasicAuth
from pycti import OpenCTIConnectorHelper
from connector_config import ConnectorConfig


class WazuhIndexerSearchClient:
    def __init__(self, config: ConnectorConfig) -> None:
        # Strips the trailing slash so request URLs stay consistent, avoids double slash issues later
        self.base_url = config.wazuh_url.rstrip("/")
        self.username = config.wazuh_username
        self.password = config.wazuh_password
        self.verify_ssl = config.wazuh_verify_ssl
        self.timeout = config.wazuh_timeout
        self.index_pattern = config.wazuh_index_pattern

    def _headers(self) -> dict[str, str]:
        # Standard header for OpenSearch queries, everything is JSON here
        return {"Content-Type": "application/json"}

    def _auth(self) -> HTTPBasicAuth:
        # Basic auth used for indexer access, tied to whatever creds that were configured
        return HTTPBasicAuth(self.username, self.password)

    def search_alerts(
        self,
        entity_type: str,
        entity_value: str,
        fields: list[str],
        lookback_days: int,
        limit: int,
    ) -> list[dict[str, Any]]:
        # If we don’t have something meaningful to search, this exits everything early
        if not entity_value or not fields:
            return []

        # Escape characters that break query_string parsing, OpenSearch is picky here
        escaped_value = entity_value.replace("\\", "\\\\").replace('"', '\\"')

        should_clauses: list[dict[str, Any]] = []
        for field in fields:
            # Builds OR logic across multiple fields, the essential core of the search behavior
            should_clauses.append(
                {
                    "query_string": {
                        "default_field": field,
                        "query": f'"{escaped_value}"',
                    }
                }
            )

        # Indicators are inconsistent, adds a broader search against full_log as fallback
        if entity_type == "Indicator":
            should_clauses.append(
                {
                    "query_string": {
                        "default_field": "full_log",
                        "query": escaped_value,
                    }
                }
            )

        # This is a time-bounded query, keeps results relevant and avoids pulling huge datasets
        body = {
            "size": limit,
            "sort": [{"timestamp": {"order": "desc"}}],
            "query": {
                "bool": {
                    "must": [
                        {
                            "range": {
                                "timestamp": {
                                    "gte": f"now-{lookback_days}d",
                                    "lte": "now",
                                }
                            }
                        }
                    ],
                    "should": should_clauses,
                    "minimum_should_match": 1,
                }
            },
        }

        url = f"{self.base_url}/{self.index_pattern}/_search"

        response = requests.get(
            url,
            headers=self._headers(),
            auth=self._auth(),
            json=body,
            verify=self.verify_ssl,
            timeout=self.timeout,
        )
        response.raise_for_status()

        payload = response.json()
        hits = payload.get("hits", {}).get("hits", [])

        # Return only the actual alert data, strips OpenSearch wrapper
        return [hit.get("_source", {}) for hit in hits if isinstance(hit, dict) and "_source" in hit]


class WazuhEnrichmentConnector:
    def __init__(self) -> None:
        # Loads config from env, this drives everything, including connector registration
        self.config = ConnectorConfig.from_env()

        # OpenCTI helper handles registration, messaging, and our API calls
        self.helper = OpenCTIConnectorHelper(self.config.as_opencti_helper_config())

        # Search client handles all of our Wazuh indexer interaction
        self.search_client = WazuhIndexerSearchClient(self.config)
        self.sighting_target_id = os.getenv("SIGHTING_TARGET_ID")

        # In-memory cache for duplicate note suppression during the current connector runtime
        self._note_cache: set[tuple[str, str]] = set()

    def _resolve_sighting_source_id(self, entity: dict[str, Any]) -> str | None:
        entity_id = entity.get("id")
        entity_type = self._entity_type(entity)

        if entity_type == "Indicator":
            return entity_id

        if entity_type in {
            "IPv4-Addr",
            "IPv6-Addr",
            "Domain-Name",
            "Url",
            "Hostname",
            "Artifact",
            "File",
            "StixFile",
        }:
            try:
                relationships = self.helper.api.stix_nested_ref_relationship.list(
                    fromId=entity_id,
                    relationship_type=None,
                    first=100,
                )
            except Exception:
                return None

            for rel in relationships:
                to = rel.get("to")
                if isinstance(to, dict) and to.get("entity_type") == "Indicator":
                    return to.get("id")

        return None

    def _safe_get(self, obj: dict[str, Any], path: str, default: Any = None) -> Any:
        # Safe nested access here, avoids a ton of repetitive checks everywhere else
        current: Any = obj
        for part in path.split("."):
            if not isinstance(current, dict):
                return default
            current = current.get(part)
            if current is None:
                return default
        return current

    def _extract_entity(self, data: dict[str, Any]) -> dict[str, Any]:
        # OpenCTI sometimes wraps entities differently depending on context, this handles them both
        return data.get("entity") or data.get("enrichment_entity") or data

    def _entity_type(self, entity: dict[str, Any]) -> str:
        return entity.get("entity_type") or entity.get("type") or ""

    def _extract_entity_value(self, entity: dict[str, Any]) -> str:
        entity_type = self._entity_type(entity)

        # Common observable types and straightforward extraction
        if entity_type in {"IPv4-Addr", "IPv6-Addr", "Domain-Name", "Url", "Hostname"}:
            return (
                entity.get("observable_value")
                or entity.get("value")
                or entity.get("name")
                or ""
            )

        # File handling, prioritizes stronger hashes first
        if entity_type in {"File", "Artifact", "StixFile"}:
            hashes = entity.get("hashes", [])
            if isinstance(hashes, list):
                preferred = ["SHA-256", "SHA-1", "MD5"]
                for algorithm in preferred:
                    for item in hashes:
                        if (
                            isinstance(item, dict)
                            and item.get("algorithm") == algorithm
                            and item.get("hash")
                        ):
                            return item["hash"]
                # Fallback, this just grabs any hash if structured ones aren’t present
                for item in hashes:
                    if isinstance(item, dict) and item.get("hash"):
                        return item["hash"]

            # Last fallback, uses additional names if present
            additional_names = entity.get("x_opencti_additional_names", [])
            if isinstance(additional_names, list) and additional_names:
                return str(additional_names[0])

            return entity.get("observable_value") or entity.get("name") or ""

        if entity_type == "Vulnerability":
            return entity.get("name") or ""

        if entity_type == "Indicator":
            # Indicators can be messy, so this tries multiple fields
            return (
                entity.get("name")
                or entity.get("observable_value")
                or entity.get("pattern")
                or ""
            )

        # Generic fallback
        return (
            entity.get("observable_value")
            or entity.get("name")
            or entity.get("value")
            or ""
        )

    def _field_map_for_entity_type(self, entity_type: str) -> list[str]:
        # Mapping between OpenCTI types and the various applicable Wazuh fields
        mapping = {
            "IPv4-Addr": [
                "data.srcip",
                "data.dstip",
                "srcip",
                "dstip",
                "data.win.eventdata.sourceIp",
                "data.win.eventdata.destinationIp",
                "full_log",
            ],
            "IPv6-Addr": [
                "data.srcip",
                "data.dstip",
                "srcip",
                "dstip",
                "data.win.eventdata.sourceIp",
                "data.win.eventdata.destinationIp",
                "full_log",
            ],
            "Indicator": [
                "data.srcip",
                "data.dstip",
                "srcip",
                "dstip",
                "data.domain",
                "data.hostname",
                "data.url",
                "data.md5",
                "data.sha1",
                "data.sha256",
                "full_log",
            ],
        }
        return mapping.get(entity_type, ["full_log"])

    def _is_private_ip(self, value: str) -> bool:
        # Skips internal IPs, prevents noisy and less useful enrichment
        try:
            ip_obj = ipaddress.ip_address(value)
            return ip_obj.is_private
        except ValueError:
            return False

    def _should_enrich(self, entity: dict[str, Any], entity_type: str, entity_value: str) -> tuple[bool, str]:
        # Enforces our scope, avoids wasting cycles on unsupported types
        if entity_type not in self.config.supported_entity_types:
            return False, f"Entity type '{entity_type}' is not in connector scope"

        if not entity_value:
            return False, f"No searchable value found for entity type '{entity_type}'"

        # Skips all private IPs, which typically aren’t useful for threat context
        if entity_type in {"IPv4-Addr", "IPv6-Addr"} and self._is_private_ip(entity_value):
            return False, f"Skipping private IP address '{entity_value}'"

        # Allows analysts to opt-out using labels
        labels = entity.get("objectLabel") or entity.get("labels") or []
        if isinstance(labels, list):
            for label in labels:
                if isinstance(label, dict):
                    label_value = (label.get("value") or "").lower()
                else:
                    label_value = str(label).lower()

                if label_value in {"ignore", "no-enrich", "skip-enrichment"}:
                    return False, f"Skipping entity due to label '{label_value}'"

        return True, "Eligible for enrichment"

    def _parse_wazuh_timestamp(self, value: str | None) -> datetime | None:
        # Parses Wazuh timestamps into datetime objects so the recency logic stays consistent
        if not value:
            return None

        for fmt in ("%Y-%m-%dT%H:%M:%S.%f%z", "%Y-%m-%dT%H:%M:%S%z"):
            try:
                return datetime.strptime(value, fmt)
            except ValueError:
                continue

        return None

    def _rule_level(self, alert: dict[str, Any]) -> int:
        # Pulls Wazuh rule level and safely converts it into an integer for later processing
        raw = self._safe_get(alert, "rule.level", 0)
        try:
            return int(raw)
        except (TypeError, ValueError):
            return 0

    def _rule_id(self, alert: dict[str, Any]) -> str:
        return str(self._safe_get(alert, "rule.id", "unknown"))

    def _rule_description(self, alert: dict[str, Any]) -> str:
        return str(self._safe_get(alert, "rule.description", "unknown"))

    def _rule_groups(self, alert: dict[str, Any]) -> list[str]:
        # Normalizes Wazuh rule groups so filtering logic stays simple later
        groups = self._safe_get(alert, "rule.groups", [])
        if isinstance(groups, list):
            return [str(x).lower() for x in groups]
        return []

    def _agent_name(self, alert: dict[str, Any]) -> str:
        return str(self._safe_get(alert, "agent.name", "unknown"))

    def _source_category(self, alert: dict[str, Any]) -> str:
        # Buckets alerts into source families so SOC summaries are more readable
        decoder = str(self._safe_get(alert, "decoder.name", "")).lower()
        location = str(self._safe_get(alert, "location", "")).lower()
        groups = self._rule_groups(alert)

        if "windows" in groups or "sysmon" in groups or "win" in decoder:
            return "windows"
        if "firewall" in groups or "sophos" in decoder or "firewall" in location:
            return "firewall"
        if "sshd" in decoder or "authentication" in groups or "pam" in decoder:
            return "authentication"
        if "dns" in groups or "dns" in decoder:
            return "dns"
        if "web" in groups or "apache" in decoder or "nginx" in decoder:
            return "web"
        return "general"

    def _filter_alerts(self, alerts: list[dict[str, Any]]) -> list[dict[str, Any]]:
        # Applies SOC tuning controls so analysts don’t get every low-value result back
        filtered: list[dict[str, Any]] = []

        allowed_groups = {item.lower() for item in self.config.allowed_rule_groups}
        allowed_categories = {item.lower() for item in self.config.allowed_source_categories}

        for alert in alerts:
            if self._rule_level(alert) < self.config.min_rule_level:
                continue

            if allowed_groups:
                groups = set(self._rule_groups(alert))
                if not groups.intersection(allowed_groups):
                    continue

            if allowed_categories:
                category = self._source_category(alert).lower()
                if category not in allowed_categories:
                    continue

            filtered.append(alert)

        return filtered

    def _cluster_alerts(self, alerts: list[dict[str, Any]]) -> list[dict[str, Any]]:
        # Groups alerts by rule and agent so the note shows patterns instead of only a raw count
        clusters: dict[tuple[str, str], dict[str, Any]] = {}

        for alert in alerts:
            rule_id = self._rule_id(alert)
            rule_desc = self._rule_description(alert)
            agent = self._agent_name(alert)
            key = (rule_id, agent)

            if key not in clusters:
                clusters[key] = {
                    "rule_id": rule_id,
                    "rule_desc": rule_desc,
                    "agent": agent,
                    "count": 0,
                    "latest": self._safe_get(alert, "timestamp", "unknown"),
                }

            clusters[key]["count"] += 1

        return sorted(
            clusters.values(),
            key=lambda x: x["count"],
            reverse=True,
        )[: self.config.cluster_limit]

    def _extract_related_observables(self, alerts: list[dict[str, Any]]) -> dict[str, list[str]]:
        # Pulls nearby observables out of matching alerts so analysts get immediate pivot points
        ips: set[str] = set()
        domains: set[str] = set()
        urls: set[str] = set()
        hashes: set[str] = set()
        users: set[str] = set()

        for alert in alerts:
            for path in [
                "data.srcip",
                "data.dstip",
                "srcip",
                "dstip",
                "data.win.eventdata.ipAddress",
                "data.win.eventdata.sourceIp",
                "data.win.eventdata.destinationIp",
            ]:
                value = self._safe_get(alert, path)
                if value:
                    ips.add(str(value))

            for path in [
                "data.url",
                "data.win.eventdata.targetUrl",
            ]:
                value = self._safe_get(alert, path)
                if value:
                    urls.add(str(value))

            for path in [
                "data.domain",
                "data.hostname",
                "data.win.eventdata.targetDomainName",
            ]:
                value = self._safe_get(alert, path)
                if value:
                    domains.add(str(value))

            for path in [
                "data.md5",
                "data.sha1",
                "data.sha256",
                "md5",
                "sha1",
                "sha256",
            ]:
                value = self._safe_get(alert, path)
                if value:
                    hashes.add(str(value))

            for path in [
                "data.srcuser",
                "data.dstuser",
                "data.win.eventdata.targetUserName",
                "data.win.eventdata.subjectUserName",
            ]:
                value = self._safe_get(alert, path)
                if value:
                    users.add(str(value))

        limit = self.config.related_observable_limit
        return {
            "ips": sorted(list(ips))[:limit],
            "domains": sorted(list(domains))[:limit],
            "urls": sorted(list(urls))[:limit],
            "hashes": sorted(list(hashes))[:limit],
            "users": sorted(list(users))[:limit],
        }

    def _score_alerts(self, alerts: list[dict[str, Any]]) -> dict[str, Any]:
        # Produces a simple triage score and severity band for analyst notes
        if not alerts:
            return {
                "score": 0,
                "severity": "none",
                "max_rule_level": 0,
                "unique_agents": 0,
                "unique_rules": 0,
                "recent_hits": 0,
                "source_categories": [],
            }

        now = datetime.now(timezone.utc)
        max_rule_level = 0
        recent_hits = 0
        agents: set[str] = set()
        rules: set[str] = set()
        categories: Counter[str] = Counter()

        for alert in alerts:
            max_rule_level = max(max_rule_level, self._rule_level(alert))
            agents.add(self._agent_name(alert))
            rules.add(self._rule_description(alert))
            categories[self._source_category(alert)] += 1

            ts = self._parse_wazuh_timestamp(self._safe_get(alert, "timestamp"))
            if ts:
                age_seconds = (now - ts).total_seconds()
                if age_seconds <= (self.config.recent_hits_window_hours * 3600):
                    recent_hits += 1

        # Score = number of alerts + severity of alerts + number of affected agents + 
        # how recent the alerts are (each part capped)
        score = 0
        score += min(len(alerts), 25)
        score += min(max_rule_level * 2, 30)
        score += min(len(agents) * 4, 20)
        score += min(recent_hits, 15)

        if max_rule_level >= 12 or len(agents) >= 5:
            severity = "High"
        elif max_rule_level >= 8 or len(alerts) >= 10:
            severity = "Medium"
        else:
            severity = "Low"

        return {
            "score": score,
            "severity": severity,
            "max_rule_level": max_rule_level,
            "unique_agents": len(agents),
            "unique_rules": len(rules),
            "recent_hits": recent_hits,
            "source_categories": [name for name, _ in categories.most_common(3)],
        }

    def _build_wazuh_hunt_query(self, entity_value: str) -> str:
        # Builds a reusable search string analysts can paste into Wazuh hunts
        escaped = entity_value.replace('"', '\\"')
        return f'timestamp:[now-{self.config.query_lookback_days}d TO now] AND "{escaped}"'

    def _build_wazuh_hunt_url(self, entity_value: str) -> str:
        # Builds a hunt URL when a base URL is configured, otherwise leaves it blank
        if not self.config.hunt_url_base:
            return ""
        return f"{self.config.hunt_url_base.rstrip('/')}/?q={quote(self._build_wazuh_hunt_query(entity_value))}"

    def _build_summary_note(
        self,
        entity_type: str,
        entity_value: str,
        alerts: list[dict[str, Any]],
    ) -> str:
        header = "Wazuh enrichment result"
        hunt_query = self._build_wazuh_hunt_query(entity_value)
        hunt_url = self._build_wazuh_hunt_url(entity_value)

        # Default alert if nothing is found for an entity
        if not alerts:
            lines = [
                header,
                "",
                "**Assessment**",
                "- Severity: none",
                "- Analyst takeaway: No matching Wazuh alerts were found for this entity in the current lookback window.",
                "",
                "**Summary**",
                f"- Entity type: {entity_type}",
                f"- Entity value: {entity_value}",
                f"- Lookback window: {self.config.query_lookback_days} days",
                "",
                "**Suggested Wazuh hunt query**",
                "",
                hunt_query,
            ]
            if hunt_url:
                lines.extend(["", "**Suggested Wazuh hunt URL**", hunt_url])
            return "\n".join(lines)

        total = len(alerts)
        last_seen = self._safe_get(alerts[0], "timestamp", "unknown")
        first_seen = self._safe_get(alerts[-1], "timestamp", "unknown")

        agent_counts: Counter[str] = Counter()
        rule_counts: Counter[str] = Counter()

        for alert in alerts:
            agent_counts[self._agent_name(alert)] += 1
            rule_counts[self._rule_description(alert)] += 1

        top_agents_list = agent_counts.most_common(self.config.cluster_limit)
        top_rules_list = rule_counts.most_common(self.config.cluster_limit)
        clusters = self._cluster_alerts(alerts)
        related = self._extract_related_observables(alerts)
        scoring = self._score_alerts(alerts)

        top_agents = (
            [f"{i + 1}. {name}: {count}" for i, (name, count) in enumerate(top_agents_list)]
            if top_agents_list
            else ["1. none"]
        )

        top_rules = (
            [f"{i + 1}. {name}: {count}" for i, (name, count) in enumerate(top_rules_list)]
            if top_rules_list
            else ["1. none"]
        )

        top_clusters = (
            [
                f"{i + 1}. Rule {item['rule_id']} on {item['agent']}: {item['count']} hits ({item['rule_desc']})"
                for i, item in enumerate(clusters)
            ]
            if clusters
            else ["1. none"]
        )

        related_lines: list[str] = []
        if related["ips"]:
            related_lines.append(f"1. Related IPs: {', '.join(related['ips'])}")
        if related["domains"]:
            related_lines.append(f"2. Related domains/hosts: {', '.join(related['domains'])}")
        if related["urls"]:
            related_lines.append(f"3. Related URLs: {', '.join(related['urls'])}")
        if related["hashes"]:
            related_lines.append(f"4. Related hashes: {', '.join(related['hashes'])}")
        if related["users"]:
            related_lines.append(f"5. Related users: {', '.join(related['users'])}")
        if not related_lines:
            related_lines = ["1. none"]

        analyst_takeaway = (
            f"This entity matched {total} Wazuh alert(s) across {scoring['unique_agents']} agent(s) "
            f"and {scoring['unique_rules']} rule pattern(s)."
        )
        lines = [
            header,
            "",
            "**Assessment**",
            f"- Severity: {scoring['severity']}",
            f"- Score: {scoring['score']}",
            f"- Analyst takeaway: {analyst_takeaway}",
            "",
            "**Summary**",
            f"- Entity type: {entity_type}",
            f"- Entity value: {entity_value}",
            f"- Lookback window: {self.config.query_lookback_days} days",
            f"- Total matches: {total}",
            f"- First seen: {first_seen}",
            f"- Last seen: {last_seen}",
            f"- Max Wazuh rule level: {scoring['max_rule_level']}",
            f"- Unique agents: {scoring['unique_agents']}",
            f"- Unique rule patterns: {scoring['unique_rules']}",
            f"- Matches in last {self.config.recent_hits_window_hours} hour(s): {scoring['recent_hits']}",
            f"- Source categories: {', '.join(scoring['source_categories']) or 'none'}",
            "",
            "**Suggested Wazuh hunt query**",
            "",
            hunt_query,
        ]

        if hunt_url:
            lines.extend(["", "**Suggested Wazuh hunt URL**", hunt_url])

        return "\n".join(lines)

    def _should_create_note(self, entity_id: str, content: str) -> bool:
        # Allows duplicate note suppression without breaking the rest of our flow
        if not self.config.deduplicate_notes:
            return True

        cache_key = (entity_id, content)
        if cache_key in self._note_cache:
            return False

        self._note_cache.add(cache_key)
        return True

    def _create_note(self, entity_id: str, content: str) -> None:
        # Creates and links analyst-facing notes when note output is enabled
        if not self.config.create_notes:
            return

        if not self._should_create_note(entity_id, content):
            self.helper.log_info(
                "Skipping duplicate Wazuh note",
                {"target_entity_id": entity_id},
            )
            return

        note = self.helper.api.note.create(
            abstract="Wazuh enrichment result",
            content=content,
        )

        note_id = note.get("id") if isinstance(note, dict) else None
        if not note_id:
            self.helper.log_warning(
                "Note was not created correctly",
                {"target_entity_id": entity_id},
            )
            return

        # This explicitly attaches the note to the object so it shows under the entity, not just in the notes section of OpenCTI
        self.helper.api.note.add_stix_object_or_stix_relationship(
            id=note_id,
            stixObjectOrStixRelationshipId=entity_id,
        )

        self.helper.log_info(
            "Created and linked Wazuh note",
            {
                "target_entity_id": entity_id,
                "note_id": note_id,
                "note_entity_type": note.get("entity_type") if isinstance(note, dict) else None,
            },
        )

    def _normalize_opencti_datetime(self, value: str | None) -> str | None:
        # Normalizes Wazuh timestamps into a format OpenCTI accepts for sightings
        if not value:
            return None

        try:
            return datetime.strptime(value, "%Y-%m-%dT%H:%M:%S.%f%z").isoformat()
        except ValueError:
            pass

        try:
            return datetime.strptime(value, "%Y-%m-%dT%H:%M:%S%z").isoformat()
        except ValueError:
            pass

        return value

    def _create_sighting(self, entity: dict[str, Any], alerts: list[dict[str, Any]]) -> None:
        # Creates a sighting when output is enabled and a usable source/target pair is available
        if not self.config.create_sightings:
            return

        source_id = self._resolve_sighting_source_id(entity)
        target_id = self.sighting_target_id

        if not source_id or not target_id or not alerts:
            return

        first_seen = self._normalize_opencti_datetime(
            self._safe_get(alerts[-1], "timestamp")
        )
        last_seen = self._normalize_opencti_datetime(
            self._safe_get(alerts[0], "timestamp")
        )
        count = len(alerts)

        try:
            self.helper.api.stix_sighting_relationship.create(
                fromId=source_id,
                toId=target_id,
                first_seen=first_seen,
                last_seen=last_seen,
                count=count,
                description=f"Wazuh enrichment found {count} matches",
            )
        except Exception as exc:
            self.helper.log_warning(f"Failed to create sighting: {exc}")

    def _process_entity(self, data: dict[str, Any]) -> str:
        # Main enrichment pipeline, everything flows through here
        entity = self._extract_entity(data)
        entity_id = entity.get("id")
        entity_type = self._entity_type(entity)
        entity_value = self._extract_entity_value(entity)

        if not entity_id:
            raise ValueError("No entity id found in enrichment payload")

        note_targets = {entity_id}

        try:
            relationships = self.helper.api.stix_nested_ref_relationship.list(
                fromId=entity_id,
                relationship_type=None,
                first=100,
            )
            for rel in relationships:
                to = rel.get("to")
                if isinstance(to, dict) and to.get("id"):
                    to_type = to.get("entity_type")
                    if to_type in {
                        "Indicator",
                        "IPv4-Addr",
                        "IPv6-Addr",
                        "Domain-Name",
                        "Url",
                        "Hostname",
                        "Artifact",
                        "File",
                        "StixFile",
                    }:
                        note_targets.add(to.get("id"))
        except Exception:
            pass

        # Decision gate, avoids unnecessary queries
        should_enrich, reason = self._should_enrich(entity, entity_type, entity_value)
        if not should_enrich:
            for target_id in note_targets:
                self._create_note(target_id, f"Wazuh enrichment skipped\n\n{reason}")
            return reason

        # Executes search
        raw_alerts = self.search_client.search_alerts(
            entity_type=entity_type,
            entity_value=entity_value,
            fields=self._field_map_for_entity_type(entity_type),
            lookback_days=self.config.query_lookback_days,
            limit=self.config.max_results,
        )

        # Applies SOC-oriented filtering before notes or sightings are generated
        alerts = self._filter_alerts(raw_alerts)

        # Builds output
        summary = self._build_summary_note(entity_type, entity_value, alerts)

        for target_id in note_targets:
            self._create_note(target_id, summary)

        if alerts:
            self._create_sighting(entity, alerts)

        return f"Completed enrichment, matches: {len(alerts)}"

    def _message_callback(self, data: dict[str, Any]) -> str:
        # Entry point from OpenCTI
        try:
            return self._process_entity(data)
        except Exception as exc:
            self.helper.log_error(f"Unhandled enrichment error: {exc}")
            raise

    def start(self) -> None:
        # Connector loop, waits for enrichment jobs
        self.helper.log_info("Starting Wazuh enrichment connector")
        self.helper.listen(message_callback=self._message_callback)

        # If listen ever returns, treat it as a failure and keep the reason visible
        raise RuntimeError("OpenCTI helper.listen() returned unexpectedly")


if __name__ == "__main__":
    try:
        connector = WazuhEnrichmentConnector()
        connector.start()
    except Exception as exc:
        print(f"FATAL: {exc}", flush=True)
        traceback.print_exc()
        time.sleep(5)
        raise