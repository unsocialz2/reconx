package report

import (
	_ "embed"
)

// htmlTemplate is the HTML report template, embedded at compile time
// from template.html. Using //go:embed avoids the need to ship the
// .html file alongside the binary — it's baked into the executable.
//
//go:embed template.html
var htmlTemplate string
