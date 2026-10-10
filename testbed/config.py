"""Parameters of the synthetic fleet-backend testbed.

Every value here was chosen by the agent under the author's delegation (2026-09-19) and is recorded as a
proposed decision in article-docs/experiments/testbed-parameters.md. Secrets below are synthetic and exist
only inside the testbed; they protect nothing.
"""

CFG = {
    # synthetic population
    "tenants": 8,
    "fleets_per_tenant": 4,
    "vehicles_per_fleet": 25,
    "operators_per_tenant": 3,
    "partners": 3,
    "legacy_share": 0.10,          # share of vehicles whose GET /vehicles/{id} lacks the object-level check
    # background traffic over one simulated day
    "day_ms": 86_400_000,
    "driver_active_prob": 0.70,
    "driver_requests": (2, 6),
    "operator_sessions": 2,
    "operator_requests": (10, 30),
    "partner_polls": (80, 140),
    "ci_campaigns": 2,
    # integrity envelope
    "batch_size": 100,
    # reconstruction
    "lookback_ms": 30 * 60 * 1000,
    # attack intensities (inclusive ranges)
    "s1_failed_logins": (3, 8),
    "s1_commands": (5, 15),
    "s1_location_reads": (3, 10),
    "s2_probes": (40, 120),
    "s3_pages": (12, 40),
    "s3_limit": 10,
    "s4_target_fleets": (2, 6),
    "s5_reads": (100, 300),
    # synthetic secrets (testbed only)
    "hmac_key": b"sim-pseudonymization-key",
    "jwt_key": "sim-token-signing-key-0123456789abcdef-synthetic",
    "token_ttl_ms": 3_600_000,
    "epoch_base": 1767225600,      # 2026-01-01T00:00:00Z
}

SCENARIOS = ("s1_takeover", "s2_bola_probing", "s3_bulk_location", "s4_ota_anomaly", "s5_supplier_abuse")

MINIMAL_FIELDS = ("ts", "account_id", "object_id", "action", "outcome")

# Steelman baseline added 2026-10-10 (CAPTOR review): what a web-server/API-gateway access log typically holds
# (combined log format plus the client id). "path" is the concrete request path with its query string; it is
# written only to this profile, so the minimal and complete profiles are byte-identical to the confirmatory runs.
ACCESS_FIELDS = ("ts", "account_id", "client_id", "object_id", "action", "outcome",
                 "route", "path", "src_ip_pseudo", "user_agent_class")

# Ablation field groups: fields whose removal disables a specific reconstruction capability.
# Used by logsink to project ablation profiles from the complete record.
SESSION_FIELDS = {"token_id", "device_id", "client_id", "subject_type"}  # Q1/Q4: session binding
OBJECT_FIELDS = {"vehicle_id", "fleet_id", "tenant_id"}  # Q2/Q5: blast radius per vehicle/fleet/tenant
CAMPAIGN_FIELDS = {"campaign_id", "artifact_id", "signature_result", "target_count", "approver_id"}  # S4: OTA forensics
ABLATION_PROFILES = {
    "abl_no_session": SESSION_FIELDS,
    "abl_no_object": OBJECT_FIELDS,
    "abl_no_campaign": CAMPAIGN_FIELDS,
}

# Fields that every gateway record of an authenticated request carries in the complete profile.
# The reconstruction checks this list to report evidence gaps; the manifest is derived from the same list.
UNIVERSAL_FIELDS = (
    "ts", "account_id", "object_id", "action", "outcome",
    "event_id", "seq", "layer", "component", "corr_id",
    "credential_id", "token_id", "client_id", "subject_type", "scope",
    "object_type", "route", "decision",
    "src_ip_pseudo", "user_agent_class", "device_id", "geo_region",
)
