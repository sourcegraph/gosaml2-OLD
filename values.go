package saml2

// Values is a type for holding Assertion Values which may be multi-valued
type Values map[string][]string

// Get is a safe method (nil maps will not panic) for returning the first value
// for an assertion key.
func (vals Values) Get(k string) string {
	if vals == nil {
		return ""
	}
	if v := vals[k]; len(v) > 0 {
		return v[0]
	}
	return ""
}

// Set replaces any pre-existing key's values (if any existed) with only the
// given value.
func (vals Values) Set(k, v string) {
	vals[k] = []string{v}
}

// Add appends to any set of values, whether or not the key existed already.
// That is, it will create a slice if none existed.
func (vals Values) Add(k, v string) {
	if _, ok := vals[k]; !ok {
		vals.Set(k, v)
		return
	}
	vals[k] = append(vals[k], v)
}
