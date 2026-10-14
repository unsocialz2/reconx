package report

import "encoding/json"

// jsonMarshalImpl is the real implementation of jsonMarshal.
// It lives in a separate file so tests can stub it if needed.
func jsonMarshalImpl(v interface{}) ([]byte, error) {
	return json.Marshal(v)
}
