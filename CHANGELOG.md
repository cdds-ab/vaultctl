# CHANGELOG


## v0.1.0 (2026-03-08)

### Features

- Initial vaultctl CLI implementation
  ([`124ba4f`](https://github.com/cdds-ab/vaultctl/commit/124ba4f99df04d0020ade93dfff66a80cd037434))

Generalized Ansible Vault management CLI with: - Commands: init, list, get, set, delete, describe,
  restore, edit, check - YAML config (.vaultctl.yml) with upward search - Password resolution chain
  (env, file, cmd) - Key metadata with expiry tracking (vault-keys.yml) - CI/CD pipeline (GitHub
  Actions), semantic-release, pre-commit hooks - 46 tests, 80% coverage
