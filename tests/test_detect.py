"""Tests for heuristic vault entry type detection."""

from __future__ import annotations

from vaultctl.detect import (
    DetectionResult,
    _collect_nested_credential_types,
    detect_all,
    detect_type_heuristic,
    filter_by_confidence,
)


class TestFieldStructureDetection:
    """Dict field patterns — highest priority, high confidence."""

    def test_username_password_fields(self):
        value = {"username": "admin", "password": "s3cret"}
        result = detect_type_heuristic("db_creds", value)
        assert result.suggested_type == "usernamePassword"
        assert result.confidence == "high"
        assert any("fields:" in s for s in result.signals)

    def test_user_password_fields(self):
        value = {"user": "admin", "password": "s3cret"}
        result = detect_type_heuristic("creds", value)
        assert result.suggested_type == "usernamePassword"
        assert result.confidence == "high"

    def test_user_pass_fields(self):
        value = {"user": "admin", "pass": "s3cret"}
        result = detect_type_heuristic("creds", value)
        assert result.suggested_type == "usernamePassword"

    def test_private_key_field(self):
        value = {"private_key": "pem-data"}
        result = detect_type_heuristic("ssh_key", value)
        assert result.suggested_type == "sshKey"
        assert result.confidence == "high"

    def test_key_field(self):
        value = {"key": "pem-data"}
        result = detect_type_heuristic("my_ssh", value)
        assert result.suggested_type == "sshKey"

    def test_certificate_field(self):
        value = {"certificate": "cert-data"}
        result = detect_type_heuristic("tls", value)
        assert result.suggested_type == "certificate"
        assert result.confidence == "high"

    def test_cert_chain_fields(self):
        value = {"certificate": "cert-data", "chain": "chain-data"}
        result = detect_type_heuristic("tls", value)
        assert result.suggested_type == "certificate"

    def test_cert_key_fields(self):
        value = {"cert": "cert-data", "key": "key-data"}
        result = detect_type_heuristic("tls", value)
        assert result.suggested_type == "certificate"

    def test_extra_fields_dont_prevent_match(self):
        value = {"username": "admin", "password": "s3cret", "host": "db.example.com"}
        result = detect_type_heuristic("db", value)
        assert result.suggested_type == "usernamePassword"

    def test_empty_dict(self):
        result = detect_type_heuristic("config", {})
        assert result.suggested_type == "secretText"
        assert result.confidence == "low"


class TestValuePatternDetection:
    """PEM headers and SSH prefixes — high confidence."""

    def test_rsa_private_key(self):
        pem = "-----BEGIN RSA PRIVATE KEY-----\nMIIEpAIBAAK..."
        result = detect_type_heuristic("key", pem)
        assert result.suggested_type == "sshKey"
        assert result.confidence == "high"
        assert any("value_pattern" in s for s in result.signals)

    def test_generic_private_key(self):
        pem = "-----BEGIN PRIVATE KEY-----\nMIIEvAIBADA..."
        result = detect_type_heuristic("key", pem)
        assert result.suggested_type == "sshKey"

    def test_openssh_private_key(self):
        pem = "-----BEGIN OPENSSH PRIVATE KEY-----\nb3Blbn..."
        result = detect_type_heuristic("key", pem)
        assert result.suggested_type == "sshKey"

    def test_ec_private_key(self):
        pem = "-----BEGIN EC PRIVATE KEY-----\nMHQCAQEE..."
        result = detect_type_heuristic("key", pem)
        assert result.suggested_type == "sshKey"

    def test_certificate_pem(self):
        pem = "-----BEGIN CERTIFICATE-----\nMIIFjTCCA3W..."
        result = detect_type_heuristic("cert", pem)
        assert result.suggested_type == "certificate"
        assert result.confidence == "high"

    def test_ssh_rsa_public_key(self):
        result = detect_type_heuristic("pubkey", "ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABgQ...")
        assert result.suggested_type == "sshKey"

    def test_ssh_ed25519_public_key(self):
        result = detect_type_heuristic("pubkey", "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAA...")
        assert result.suggested_type == "sshKey"

    def test_value_in_dict_field(self):
        """PEM in a dict's private_key field should be detected."""
        value = {"private_key": "-----BEGIN RSA PRIVATE KEY-----\nMIIE..."}
        result = detect_type_heuristic("my_key", value)
        # Should match on field structure first (high), not value
        assert result.suggested_type == "sshKey"
        assert result.confidence == "high"

    def test_non_matching_string(self):
        result = detect_type_heuristic("some_key", "just-a-password")
        assert result.suggested_type == "secretText"


class TestKeyNamePatternDetection:
    """Key name patterns — medium confidence fallback."""

    def test_password_suffix(self):
        result = detect_type_heuristic("db_password", "secret")
        assert result.suggested_type == "usernamePassword"
        assert result.confidence == "medium"

    def test_pass_suffix(self):
        result = detect_type_heuristic("admin_pass", "secret")
        assert result.suggested_type == "usernamePassword"

    def test_credentials_suffix(self):
        result = detect_type_heuristic("api_credentials", "secret")
        assert result.suggested_type == "usernamePassword"

    def test_ssh_prefix(self):
        result = detect_type_heuristic("ssh_deploy_key", "key-data")
        assert result.suggested_type == "sshKey"

    def test_privkey_suffix(self):
        result = detect_type_heuristic("server_privkey", "key-data")
        assert result.suggested_type == "sshKey"

    def test_cert_suffix(self):
        result = detect_type_heuristic("server_cert", "cert-data")
        assert result.suggested_type == "certificate"

    def test_certificate_suffix(self):
        result = detect_type_heuristic("tls_certificate", "cert-data")
        assert result.suggested_type == "certificate"

    def test_ssl_cert(self):
        result = detect_type_heuristic("ssl_cert", "cert-data")
        assert result.suggested_type == "certificate"

    def test_no_match(self):
        result = detect_type_heuristic("api_token", "tok-123")
        assert result.suggested_type == "secretText"
        assert result.confidence == "low"

    def test_case_insensitive(self):
        result = detect_type_heuristic("DB_PASSWORD", "secret")
        assert result.suggested_type == "usernamePassword"


class TestExplicitType:
    """Entries with an explicit type field should be skipped."""

    def test_explicit_type_skipped(self):
        value = {"type": "usernamePassword", "username": "u", "password": "p"}
        result = detect_type_heuristic("creds", value)
        assert result.skipped is True
        assert result.suggested_type == "usernamePassword"
        assert result.current_type == "usernamePassword"
        assert "explicit_type" in result.signals

    def test_explicit_custom_type(self):
        value = {"type": "customType", "data": "stuff"}
        result = detect_type_heuristic("entry", value)
        assert result.skipped is True
        assert result.suggested_type == "customType"


class TestDetectAll:
    def test_mixed_vault(self):
        data = {
            "plain_secret": "password123",
            "db_creds": {"username": "admin", "password": "s3cret"},
            "ssh_key": "-----BEGIN RSA PRIVATE KEY-----\nMIIE...",
            "typed_entry": {"type": "certificate", "cert": "data"},
        }
        results = detect_all(data)
        by_key = {r.key: r for r in results}

        assert by_key["plain_secret"].suggested_type == "secretText"
        assert by_key["db_creds"].suggested_type == "usernamePassword"
        assert by_key["ssh_key"].suggested_type == "sshKey"
        assert by_key["typed_entry"].skipped is True

    def test_previous_keys_skipped(self):
        data = {
            "my_key": "value",
            "my_key_previous": "old_value",
        }
        results = detect_all(data)
        by_key = {r.key: r for r in results}

        assert by_key["my_key_previous"].skipped is True
        assert "backup_key" in by_key["my_key_previous"].signals

    def test_empty_vault(self):
        assert detect_all({}) == []

    def test_sorted_output(self):
        data = {"z_key": "v", "a_key": "v", "m_key": "v"}
        results = detect_all(data)
        keys = [r.key for r in results]
        assert keys == sorted(keys)

    def test_all_entries_get_result(self):
        data = {"k1": "v1", "k2": {"a": "b"}, "k3": "v3"}
        results = detect_all(data)
        assert len(results) == 3


class TestPriorityOrder:
    """Field structure should take priority over value patterns and key names."""

    def test_fields_over_key_name(self):
        """Dict with username+password should be usernamePassword even if key says 'cert'."""
        value = {"username": "admin", "password": "pass"}
        result = detect_type_heuristic("my_cert", value)
        assert result.suggested_type == "usernamePassword"

    def test_fields_over_value_pattern(self):
        """Dict with certificate field wins even if value looks like SSH key."""
        value = {"certificate": "-----BEGIN RSA PRIVATE KEY-----\ndata"}
        result = detect_type_heuristic("key", value)
        assert result.suggested_type == "certificate"

    def test_value_over_key_name(self):
        """PEM header should win over key name pattern."""
        result = detect_type_heuristic(
            "db_password",
            "-----BEGIN CERTIFICATE-----\nMIIF...",
        )
        assert result.suggested_type == "certificate"


class TestFilterByConfidence:
    """Tests for filter_by_confidence helper."""

    @staticmethod
    def _make_results() -> list[DetectionResult]:
        return [
            DetectionResult(key="a", current_type=None, suggested_type="sshKey", confidence="high", signals=[]),
            DetectionResult(
                key="b", current_type=None, suggested_type="usernamePassword", confidence="medium", signals=[]
            ),
            DetectionResult(key="c", current_type=None, suggested_type="secretText", confidence="low", signals=[]),
        ]

    def test_filter_low_returns_all(self) -> None:
        results = self._make_results()
        filtered = filter_by_confidence(results, "low")
        assert len(filtered) == 3

    def test_filter_medium_excludes_low(self) -> None:
        results = self._make_results()
        filtered = filter_by_confidence(results, "medium")
        assert len(filtered) == 2
        assert all(r.confidence in ("high", "medium") for r in filtered)

    def test_filter_high_only_high(self) -> None:
        results = self._make_results()
        filtered = filter_by_confidence(results, "high")
        assert len(filtered) == 1
        assert filtered[0].confidence == "high"

    def test_empty_list(self) -> None:
        assert filter_by_confidence([], "high") == []


class TestRecursiveCredentialStoreDetection:
    """Nested credential structures should be detected as credentialStore."""

    def test_jenkins_global_credentials(self):
        """Jenkins JCasC global credentials structure."""
        value = {
            "global": {
                "credentials": [
                    {"type": "usernamePassword", "id": "cred1", "username": "u", "password": "p"},
                    {"type": "string", "id": "cred2", "secret": "s"},
                    {"type": "usernamePassword", "id": "cred3", "username": "u2", "password": "p2"},
                ]
            }
        }
        result = detect_type_heuristic("vault_jenkins_credentials", value)
        assert result.suggested_type == "credentialStore"
        assert result.confidence == "high"
        assert result.sub_types == {"usernamePassword": 2, "string": 1}
        assert any("nested_credentials" in s for s in result.signals)

    def test_jenkins_global_and_domains(self):
        """Full Jenkins structure with both global and domain credentials."""
        value = {
            "global": {
                "credentials": [
                    {"type": "gitLabApiTokenImpl", "id": "gl1", "apiToken": "t"},
                    {"type": "usernamePassword", "id": "cred1", "username": "u", "password": "p"},
                    {"type": "string", "id": "s1", "secret": "s"},
                    {"type": "azure", "id": "az1", "clientId": "c", "clientSecret": "cs"},
                ]
            },
            "domains": [
                {
                    "name": "example.com",
                    "credentials": [
                        {"type": "usernamePassword", "id": "d1", "username": "u", "password": "p"},
                        {"type": "usernamePassword", "id": "d2", "username": "u2", "password": "p2"},
                    ],
                }
            ],
        }
        result = detect_type_heuristic("vault_jenkins_credentials", value)
        assert result.suggested_type == "credentialStore"
        assert result.confidence == "high"
        assert result.sub_types == {
            "usernamePassword": 3,
            "gitLabApiTokenImpl": 1,
            "string": 1,
            "azure": 1,
        }

    def test_deeply_nested_credentials(self):
        """Credentials nested multiple levels deep."""
        value = {
            "level1": {
                "level2": {
                    "credentials": [
                        {"type": "sshKey", "id": "k1", "privateKey": "pk"},
                    ]
                }
            }
        }
        result = detect_type_heuristic("deep_creds", value)
        assert result.suggested_type == "credentialStore"
        assert result.sub_types == {"sshKey": 1}

    def test_no_typed_items_not_credential_store(self):
        """Lists of dicts without type fields should not trigger credentialStore."""
        value = {
            "servers": [
                {"host": "a.example.com", "port": 443},
                {"host": "b.example.com", "port": 443},
            ]
        }
        result = detect_type_heuristic("server_list", value)
        assert result.suggested_type != "credentialStore"

    def test_credential_store_not_skipped(self):
        """credentialStore results should not be skipped (they are actionable)."""
        value = {
            "credentials": [
                {"type": "string", "id": "s1", "secret": "v"},
            ]
        }
        result = detect_type_heuristic("cred_store", value)
        assert result.suggested_type == "credentialStore"
        assert result.skipped is False

    def test_detect_all_includes_credential_store(self):
        """detect_all should produce credentialStore for nested entries."""
        data = {
            "simple_secret": "password123",
            "jenkins_creds": {
                "global": {
                    "credentials": [
                        {"type": "usernamePassword", "id": "c1", "username": "u", "password": "p"},
                        {"type": "string", "id": "c2", "secret": "s"},
                    ]
                }
            },
        }
        results = detect_all(data)
        by_key = {r.key: r for r in results}
        assert by_key["jenkins_creds"].suggested_type == "credentialStore"
        assert by_key["jenkins_creds"].sub_types == {"usernamePassword": 1, "string": 1}
        assert by_key["simple_secret"].suggested_type == "secretText"

    def test_explicit_top_level_type_takes_precedence(self):
        """A dict with its own top-level type field should still be skipped."""
        value = {
            "type": "customContainer",
            "credentials": [
                {"type": "string", "id": "s1", "secret": "v"},
            ],
        }
        result = detect_type_heuristic("typed_entry", value)
        assert result.skipped is True
        assert result.suggested_type == "customContainer"

    def test_empty_credential_list_not_credential_store(self):
        """An empty credentials list should not trigger credentialStore."""
        value = {"global": {"credentials": []}}
        result = detect_type_heuristic("empty_store", value)
        assert result.suggested_type != "credentialStore"

    def test_sub_types_default_empty(self):
        """Regular detection results should have empty sub_types."""
        result = detect_type_heuristic("plain_key", "some_value")
        assert result.sub_types == {}


class TestRecursionLimit:
    """Recursion depth limit prevents stack overflow on adversarial input."""

    def test_collect_nested_stops_at_depth_limit(self):
        """_collect_nested_credential_types returns empty dict beyond depth 50."""
        # Build a structure nested 60 levels deep with a credential at the bottom.
        value: dict[str, object] = {"credentials": [{"type": "sshKey", "id": "k1"}]}
        for _ in range(60):
            value = {"nested": value}

        result = _collect_nested_credential_types(value)
        # The credential is deeper than the limit — should not be found.
        assert result == {}

    def test_collect_nested_works_within_limit(self):
        """Structures within the depth limit are still detected correctly."""
        # Build a structure nested 10 levels deep — well within the limit.
        value: dict[str, object] = {"credentials": [{"type": "certificate", "id": "c1"}]}
        for _ in range(10):
            value = {"nested": value}

        result = _collect_nested_credential_types(value)
        assert result == {"certificate": 1}

    def test_collect_nested_explicit_depth_param(self):
        """Passing _depth near the limit causes early termination."""
        value: dict[str, object] = {"credentials": [{"type": "sshKey", "id": "k1"}]}
        result = _collect_nested_credential_types(value, _depth=51)
        assert result == {}
