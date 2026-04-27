// Default permissive schema for vault.yml content
//
// Vault values can be plain strings or structured objects (typed entries).
// Projects that want stricter rules — e.g. enforce minimum password length,
// require specific subfields — override this by placing a custom .cue file
// at .vaultctl/vault.cue with a top-level #VaultFile definition.

package vaultctl

#VaultEntry: string | {
	...
}

#VaultFile: {
	[string]: #VaultEntry
}
