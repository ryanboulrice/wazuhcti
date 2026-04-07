# This acts as a configuration file for connector.py, providing overall functionality
# for the script. 

# Ryan Boulrice - Netizen Corporation
# 3/31/2026

from dataclasses import dataclass, field
from typing import List
import os


def _get_env(name: str, default: str | None = None, required: bool = False) -> str:
    # Pulls environment variable, applies default if missing, raises if required and empty
    value = os.getenv(name, default)
    if required and (value is None or value == ""):
        raise ValueError(f"Missing required environment variable: {name}")
    return value or ""


def _get_bool(name: str, default: bool = False) -> bool:
    # Converts environment variable into boolean, supports common truthy values
    value = os.getenv(name)
    if value is None:
        return default
    return value.strip().lower() in {"1", "true", "yes", "y", "on"}


def _get_int(name: str, default: int) -> int:
    # Converts environment variable into integer, raises if invalid format
    value = os.getenv(name)
    if value is None or value == "":
        return default
    try:
        return int(value)
    except ValueError as exc:
        raise ValueError(f"Environment variable {name} must be an integer") from exc


def _get_list(name: str, default: List[str] | None = None) -> List[str]:
    # Splits comma-separated values into list, trims whitespace, removes empty entries
    value = os.getenv(name)
    if value is None or value.strip() == "":
        return default[:] if default else []
    return [item.strip() for item in value.split(",") if item.strip()]


@dataclass
class ConnectorConfig:
    # Core OpenCTI connection settings
    opencti_url: str
    opencti_token: str

    # Connector identity and registration fields
    connector_id: str
    connector_name: str
    connector_type: str
    connector_scope: List[str]

    # Connector behavior flags, control how enrichment runs and interacts with OpenCTI
    connector_auto: bool = False
    connector_auto_update: bool = False
    connector_only_contextual: bool = False
    connector_playbook_compatible: bool = False
    connector_enrichment_resolution: str = "entity"
    connector_log_level: str = "warning"

    # Wazuh indexer connection settings, used for querying alert data
    wazuh_url: str = ""
    wazuh_username: str = ""
    wazuh_password: str = ""
    wazuh_verify_ssl: bool = False
    wazuh_timeout: int = 30
    wazuh_index_pattern: str = "wazuh-alerts-4.x*"

    # Query tuning settings, control how far back and how much data is pulled
    query_lookback_days: int = 30
    max_results: int = 10000

    # SOC tuning controls, used by enrichment logic to shape output and filtering
    min_rule_level: int = 0
    recent_hits_window_hours: int = 24
    cluster_limit: int = 5
    related_observable_limit: int = 10

    # Output controls, determines what the connector writes back into OpenCTI
    create_notes: bool = True
    create_sightings: bool = True
    deduplicate_notes: bool = False

    # Optional enhancements for analyst workflows and filtering
    hunt_url_base: str = ""
    allowed_rule_groups: List[str] = field(default_factory=list)
    allowed_source_categories: List[str] = field(default_factory=list)

    # Supported entity types, derived from connector scope
    supported_entity_types: List[str] = field(default_factory=list)

    @classmethod
    def from_env(cls) -> "ConnectorConfig":
        # Builds connector scope, defaults to wide coverage across common observable types
        scope = _get_list(
            "CONNECTOR_SCOPE",
            default=[
                "Artifact",
                "Directory",
                "Domain-Name",
                "Email-Addr",
                "Hostname",
                "IPv4-Addr",
                "IPv6-Addr",
                "Mac-Addr",
                "Network-Traffic",
                "Process",
                "StixFile",
                "Url",
                "User-Account",
                "User-Agent",
                "Windows-Registry-Key",
                "Windows-Registry-Value-Type",
                "Vulnerability",
                "Indicator",
            ],
        )

        # Constructs config object directly from environment variables, enforces required fields
        return cls(
            opencti_url=_get_env("OPENCTI_URL", required=True),
            opencti_token=_get_env("OPENCTI_TOKEN", required=True),

            connector_id=_get_env("CONNECTOR_ID", required=True),
            connector_name=_get_env("CONNECTOR_NAME", default="Wazuh"),
            connector_type=_get_env("CONNECTOR_TYPE", default="INTERNAL_ENRICHMENT"),
            connector_scope=scope,

            connector_auto=_get_bool("CONNECTOR_AUTO", default=False),
            connector_auto_update=_get_bool("CONNECTOR_AUTO_UPDATE", default=False),
            connector_only_contextual=_get_bool("CONNECTOR_ONLY_CONTEXTUAL", default=False),
            connector_playbook_compatible=_get_bool("CONNECTOR_PLAYBOOK_COMPATIBLE", default=False),

            # Controls how enrichment attaches to entities, missing or None will break connector validation
            connector_enrichment_resolution=_get_env(
                "CONNECTOR_ENRICHMENT_RESOLUTION",
                default="entity",
            ),

            connector_log_level=_get_env("CONNECTOR_LOG_LEVEL", default="warning"),

            wazuh_url=_get_env("WAZUH_URL", required=True),
            wazuh_username=_get_env("WAZUH_USERNAME", required=True),
            wazuh_password=_get_env("WAZUH_PASSWORD", required=True),
            wazuh_verify_ssl=_get_bool("WAZUH_VERIFY_SSL", default=False),
            wazuh_timeout=_get_int("WAZUH_TIMEOUT", default=30),
            wazuh_index_pattern=_get_env("WAZUH_INDEX_PATTERN", default="wazuh-alerts-4.x*"),

            query_lookback_days=_get_int("QUERY_LOOKBACK_DAYS", default=30),
            max_results=_get_int("MAX_RESULTS", default=50),

            # SOC tuning values, used inside connector.py scoring, clustering, and filtering logic
            min_rule_level=_get_int("MIN_RULE_LEVEL", default=0),
            recent_hits_window_hours=_get_int("RECENT_HITS_WINDOW_HOURS", default=24),
            cluster_limit=_get_int("CLUSTER_LIMIT", default=5),
            related_observable_limit=_get_int("RELATED_OBSERVABLE_LIMIT", default=10),

            # Output controls, allows turning off notes or sightings without modifying code
            create_notes=_get_bool("CREATE_NOTES", default=True),
            create_sightings=_get_bool("CREATE_SIGHTINGS", default=True),
            deduplicate_notes=_get_bool("DEDUPLICATE_NOTES", default=False),

            # Optional filters, allows narrowing enrichment to specific Wazuh signal types
            hunt_url_base=_get_env("HUNT_URL_BASE", default=""),
            allowed_rule_groups=_get_list("ALLOWED_RULE_GROUPS", default=[]),
            allowed_source_categories=_get_list("ALLOWED_SOURCE_CATEGORIES", default=[]),

            # Mirrors scope so enrichment checks stay consistent with connector registration
            supported_entity_types=scope,
        )

    def as_opencti_helper_config(self) -> dict:
        # Converts internal config into structure expected by OpenCTIConnectorHelper
        return {
            "opencti": {
                "url": self.opencti_url,
                "token": self.opencti_token,
            },
            "connector": {
                "id": self.connector_id,
                "name": self.connector_name,
                "type": self.connector_type,
                "scope": ",".join(self.connector_scope),

                # These flags directly influence how OpenCTI schedules and executes enrichment jobs
                "auto": self.connector_auto,
                "only_contextual": self.connector_only_contextual,
                "playbook_compatible": self.connector_playbook_compatible,
                "log_level": self.connector_log_level,
                "auto_update": self.connector_auto_update,

                # This field must be present, missing or None will cause connector validation failure
                "enrichment_resolution": self.connector_enrichment_resolution,
            },
        }
