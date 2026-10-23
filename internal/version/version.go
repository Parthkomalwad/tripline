// Package version holds the project name and build version.
package version

// Name is the project name. Change it here to rename the binary's output.
const Name = "tripline"

// Version is set at build time with -ldflags "-X".
var Version = "dev"
