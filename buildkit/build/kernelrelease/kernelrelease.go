package kernelrelease

import (
	"regexp"
	"strings"
)

var (
	kernelVersionPattern = regexp.MustCompile(`(?P<fullversion>^(?P<version>0|[1-9]\d*)\.(?P<patchlevel>0|[1-9]\d*)\.(?P<sublevel>0|[1-9]\d*))(?P<fulltail>-(?P<fullextraversion>(?P<extraversion>0|[1-9]\d*|\d*[a-zA-Z-][0-9a-zA-Z-]*)((\.[0-9]*)*))(?P<tail>(\.(0|[1-9]\d*|\d*[a-zA-Z-][0-9a-zA-Z-_]*))*))?(\+[0-9a-zA-Z-]+(\.[0-9a-zA-Z-]+)*)?$`)
)

// KernelRelease contains all the version parts.
type KernelRelease struct {
	Fullversion string
	Version     string
	PatchLevel  string
	Sublevel    string

	Extraversion     string
	FullExtraversion string
	Tail             string
}

// IsGKE tells whether the current kernel release is for GKE by looking at its name.
func (kr *KernelRelease) IsGKE() bool {
	return strings.HasSuffix(kr.Extraversion, "gke")
}

// FromString extracts a KernelRelease object from string.
func FromString(kernelVersionStr string) KernelRelease {
	kv := KernelRelease{}
	match := kernelVersionPattern.FindStringSubmatch(kernelVersionStr)
	identifiers := make(map[string]string)
	for i, name := range kernelVersionPattern.SubexpNames() {
		if i > 0 && i <= len(match) {
			identifiers[name] = match[i]
			switch name {
			case "fullversion":
				kv.Fullversion = match[i]
			case "version":
				kv.Version = match[i]
			case "patchlevel":
				kv.PatchLevel = match[i]
			case "sublevel":
				kv.Sublevel = match[i]
			case "extraversion":
				kv.Extraversion = match[i]
			case "fullextraversion":
				kv.FullExtraversion = match[i]
			case "tail":
				kv.Tail = match[i]
			}
		}
	}

	return kv
}
