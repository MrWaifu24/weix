// Package data embeds the curated event knowledge base shipped with weix.
package data

import "embed"

// FS holds the YAML knowledge base: events/*.yaml plus lookup tables.
//
//go:embed events/*.yaml logon_types.yaml status_codes.yaml mitre.yaml
var FS embed.FS
