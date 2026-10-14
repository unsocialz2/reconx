package js

import (
	"testing"
)

func TestIsValidSecretValue(t *testing.T) {
	// These are actual false positives from the myfitnesspal scan log
	falsePositives := []string{
		"[authToken = null]",
		"[apiKey=e]",
		"[ApiKey = config]",
		"[apiKey:nB]",
		"[refresh_token:n]",
		"[access_token:t]",
		"AIDAAAAAAAAAAAAAAAAA",
		"-----BEGIN PRIVATE KEY-----\"))throw TypeError('\"pkcs8\" must be PKCS#8 formatted string')",
		"rundoublec25k",
		"null",
		"undefined",
		"true",
		"false",
		"options",
		"this.apiKey",
	}

	for _, fp := range falsePositives {
		if isValidSecretValue(fp) {
			t.Errorf("isValidSecretValue(%q) = true, want false (false positive)", fp)
		}
	}

	// These are genuine secrets that should pass
	realSecrets := []string{
		"bearer_token_9918273645a4b3c2d1e0f",
		"secret_key_prod_882910384756201938475",
		"jwt_signature_payload_h8392jf83h20dj",
		"super_secret_production_password_2024",
	}

	for _, sec := range realSecrets {
		if !isValidSecretValue(sec) {
			t.Errorf("isValidSecretValue(%q) = false, want true (valid secret)", sec)
		}
	}
}
