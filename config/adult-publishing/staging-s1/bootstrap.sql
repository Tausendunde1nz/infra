BEGIN;

REVOKE CONNECT ON DATABASE tu1nz_adult_s1 FROM PUBLIC;
GRANT CONNECT ON DATABASE tu1nz_adult_s1 TO "tu1nz-adult-s1";
REVOKE CREATE ON SCHEMA public FROM PUBLIC;

INSERT INTO creators (
    creator_id, telegram_user_id, account_status, country_policy,
    display_mode, created_at, updated_at
) VALUES (
    '79000000-0000-4000-8000-000000000101', NULL, 'ACTIVE', 'DE',
    'ANONYMOUS', now(), now()
);

INSERT INTO policy_versions (
    policy_version, status, effective_at, configuration_reference, created_at
) VALUES (
    'm3.7-synthetic-policy-v1', 'ACTIVE',
    TIMESTAMPTZ '2026-01-01 00:00:00+00',
    'urn:synthetic:m39-staging-s1-policy', now()
);

INSERT INTO country_policy_rules (
    policy_version, country_code, outcome, reason_code
) VALUES (
    'm3.7-synthetic-policy-v1', 'DE', 'ALLOW', 'SYNTHETIC_ALLOW'
);

INSERT INTO platform_policy_rules (
    policy_version, platform, country_scope, enabled, outcome,
    allowed_content_classes, configuration_reference
) VALUES
    ('m3.7-synthetic-policy-v1', 'REDDIT', 'DE', TRUE, 'ALLOW',
     ARRAY['C3_SEXUAL_ACTIVITY'], 'urn:synthetic:m39-staging-s1-policy'),
    ('m3.7-synthetic-policy-v1', 'TELEGRAM', 'DE', TRUE, 'ALLOW',
     ARRAY['C3_SEXUAL_ACTIVITY'], 'urn:synthetic:m39-staging-s1-policy'),
    ('m3.7-synthetic-policy-v1', 'X', 'DE', TRUE, 'ALLOW',
     ARRAY['C3_SEXUAL_ACTIVITY'], 'urn:synthetic:m39-staging-s1-policy');

INSERT INTO integration_accounts (
    integration_account_id, provider, environment, provider_account_id,
    contract_version, status, created_at
) VALUES
    ('79000000-0000-4000-8000-000000000111', 'REDDIT', 'TEST', 790001,
     'reddit-data-api+tu1nz-m3.4-reddit-synthetic-v1', 'ACTIVE', now()),
    ('79000000-0000-4000-8000-000000000112', 'TELEGRAM', 'TEST', 790002,
     'telegram-bot-api-10.3+tu1nz-m3.4-synthetic-v1', 'ACTIVE', now()),
    ('79000000-0000-4000-8000-000000000113', 'X', 'TEST', 790003,
     'x-api-v2+tu1nz-m3.4-x-synthetic-v1', 'ACTIVE', now());

INSERT INTO publication_destinations (
    publication_destination_id, integration_account_id, platform, environment,
    destination_key, destination_reference_digest, contract_version, status,
    created_at
) VALUES
    ('79000000-0000-4000-8000-000000000121',
     '79000000-0000-4000-8000-000000000111', 'REDDIT', 'TEST',
     'm39-reddit-synthetic-destination', repeat('a', 64),
     'reddit-data-api+tu1nz-m3.4-reddit-synthetic-v1', 'ACTIVE', now()),
    ('79000000-0000-4000-8000-000000000122',
     '79000000-0000-4000-8000-000000000112', 'TELEGRAM', 'TEST',
     'm39-telegram-synthetic-destination', repeat('b', 64),
     'telegram-bot-api-10.3+tu1nz-m3.4-synthetic-v1', 'ACTIVE', now()),
    ('79000000-0000-4000-8000-000000000123',
     '79000000-0000-4000-8000-000000000113', 'X', 'TEST',
     'm39-x-synthetic-destination', repeat('c', 64),
     'x-api-v2+tu1nz-m3.4-x-synthetic-v1', 'ACTIVE', now());

GRANT USAGE ON SCHEMA public TO "tu1nz-adult-s1";
GRANT SELECT, INSERT, UPDATE, DELETE ON ALL TABLES IN SCHEMA public
    TO "tu1nz-adult-s1";
GRANT USAGE, SELECT, UPDATE ON ALL SEQUENCES IN SCHEMA public
    TO "tu1nz-adult-s1";
GRANT EXECUTE ON ALL FUNCTIONS IN SCHEMA public TO "tu1nz-adult-s1";
ALTER DEFAULT PRIVILEGES FOR ROLE postgres IN SCHEMA public
    GRANT SELECT, INSERT, UPDATE, DELETE ON TABLES TO "tu1nz-adult-s1";
ALTER DEFAULT PRIVILEGES FOR ROLE postgres IN SCHEMA public
    GRANT USAGE, SELECT, UPDATE ON SEQUENCES TO "tu1nz-adult-s1";
ALTER DEFAULT PRIVILEGES FOR ROLE postgres IN SCHEMA public
    GRANT EXECUTE ON FUNCTIONS TO "tu1nz-adult-s1";

COMMIT;
