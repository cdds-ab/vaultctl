// Schema for .vaultctl/config.yml
//
// Closed definitions — unknown top-level keys or typos are rejected.
// All fields are optional because vaultctl ships sensible defaults; the schema
// only constrains type and structure when fields are present.

package vaultctl

#PasswordConfig: {
	env?:  string
	file?: string
	cmd?:  string
}

#AIConfig: {
	endpoint?:          string
	model?:             string
	api_key_cmd?:       string
	consent?:           bool
	consent_timestamp?: string
}

#Config: {
	vault_file?: string
	keys_file?:  string
	password?:   #PasswordConfig
	ai?:         #AIConfig
}
