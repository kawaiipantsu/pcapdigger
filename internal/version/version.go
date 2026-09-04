// Package version holds build-time metadata injected via -ldflags.
package version

var (
	Version = "dev"
	Commit  = "unknown"
	Date    = "unknown"
)

// String returns a human-readable version line.
func String() string {
	return "pcapdigger " + Version + " (commit " + Commit + ", built " + Date + ")"
}
