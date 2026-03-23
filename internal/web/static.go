package web

import "embed"

// StaticFS contains the embedded static assets (CSS, JS) served under /static/.
//
//go:embed static
var StaticFS embed.FS
