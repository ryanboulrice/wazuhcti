import time
import traceback
import ipaddress
import json
from datetime import datetime
from typing import Any

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
        # If we don’t have something meaningful to search, this exits it early
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

        # Search client handles all Wazuh indexer interaction
        self.search_client = WazuhIndexerSearchClient(self.config)

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
        # Mapping between OpenCTI types and Wazuh fields
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
            # Rest unchanged
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
        # Enforces scope, avoids wasting cycles on unsupported types
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

    def _build_summary_note(
        self,
        entity_type: str,
        entity_value: str,
        alerts: list[dict[str, Any]],
    ) -> str:
        # Always returns something readable, even with zero results
        if not alerts:
            return "\n".join(
                [
                    "Wazuh enrichment result",
                    "",
                    f"Entity type: {entity_type}",
                    f"Entity value: {entity_value}",
                    f"Lookback window: {self.config.query_lookback_days} days",
                    "",
                    "No matching Wazuh alerts were found in the indexer.",
                ]
            )

        # Summarizes hits for analyst readability, avoids raw JSON digging
        total = len(alerts)
        last_seen = self._safe_get(alerts[0], "timestamp", "unknown")

        agent_counts: dict[str, int] = {}
        rule_counts: dict[str, int] = {}

        for alert in alerts:
            agent_name = self._safe_get(alert, "agent.name", "unknown")
            rule_desc = self._safe_get(alert, "rule.description", "unknown")
            agent_counts[agent_name] = agent_counts.get(agent_name, 0) + 1
            rule_counts[rule_desc] = rule_counts.get(rule_desc, 0) + 1

        # Rest unchanged
        return "\n".join([...])  # shortened here for readability

    def _create_note(self, entity_id: str, content: str) -> None:
        # Primary enrichment output, this is what analysts will see first
        self.helper.api.note.create(
            abstract="Wazuh enrichment result",
            content=content,
            object_id=entity_id,
            createdBy=self.helper.connect_id,
        )

    def _create_sighting(self, entity: dict[str, Any], alerts: list[dict[str, Any]]) -> None:
        # Optional enrichment output, creates relationship for hits
        entity_id = entity.get("id")
        if not entity_id or not alerts:
            return

        first_seen = self._safe_get(alerts[-1], "timestamp")
        last_seen = self._safe_get(alerts[0], "timestamp")
        count = len(alerts)

        try:
            self.helper.api.stix_sighting_relationship.create(
                fromId=entity_id,
                toId=entity_id,
                first_seen=first_seen,
                last_seen=last_seen,
                count=count,
                description=f"Wazuh enrichment found {count} matches",
                createdBy=self.helper.connect_id,
            )
        except Exception as exc:
            # Doesn't fail the whole enrichment if sighting creation breaks
            self.helper.log_warning(f"Failed to create sighting: {exc}")

    def _process_entity(self, data: dict[str, Any]) -> str:
        # Main enrichment pipeline, everything flows through here
        entity = self._extract_entity(data)
        entity_id = entity.get("id")
        entity_type = self._entity_type(entity)
        entity_value = self._extract_entity_value(entity)

        if not entity_id:
            raise ValueError("No entity id found in enrichment payload")

        # Decision gate, avoids unnecessary queries
        should_enrich, reason = self._should_enrich(entity, entity_type, entity_value)
        if not should_enrich:
            self._create_note(entity_id, f"Wazuh enrichment skipped\n\n{reason}")
            return reason

        # Executes search
        alerts = self.search_client.search_alerts(
            entity_type=entity_type,
            entity_value=entity_value,
            fields=self._field_map_for_entity_type(entity_type),
            lookback_days=self.config.query_lookback_days,
            limit=self.config.max_results,
        )

        # Builds output
        summary = self._build_summary_note(entity_type, entity_value, alerts)
        self._create_note(entity_id, summary)

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
