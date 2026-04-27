// Schema for vault-keys.yml metadata
//
// Closed key-metadata definition — typos in field names ("rotat", "expries")
// are rejected. The known entry types match vaultctl/types.py.

package vaultctl

import "time"

#KeyType: "usernamePassword" | "sshKey" | "certificate" | "secretText"

#KeyMetadata: {
	description?: string
	type?:        #KeyType
	rotate?:      string
	// Accept either "YYYY-MM-DD" or full RFC 3339 timestamps.
	expires?:    time.Format("2006-01-02") | time.Format(time.RFC3339)
	consumers?:  [...string]
	rotate_cmd?: string
}

#KeysFile: {
	vault_keys: {
		[string]: #KeyMetadata
	}
}
