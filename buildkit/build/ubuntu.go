package build

import (
	"bytes"
	"fmt"
	"io/ioutil"
	"net/http"
	"regexp"
	"strings"
	"text/template"

	"github.com/chaos-mesh/chaos-driver/buildkit/build/kernelrelease"
)

func init() {
	Targets["ubuntu-generic"] = &ubuntuGeneric{}
	Targets["ubuntu-aws"] = &ubuntuAWS{}
}

// ubuntuGeneric is a driverkit target.
type ubuntuGeneric struct {
}

// Script compiles the script to build the kernel module and/or the eBPF probe.
func (v ubuntuGeneric) Script(release string, buildDir string, kv uint16) (string, error) {
	t := template.New("ubuntu-generic-build-template")
	parsed, err := t.Parse(ubuntuTemplate)
	if err != nil {
		return "", err
	}

	kr := kernelrelease.FromString(release)

	urls, _ := ubuntuGenericHeadersURLFromRelease(kr, kv)
	if len(urls) != 2 {
		return "", fmt.Errorf("specific kernel headers not found")
	}

	td := ubuntuTemplateData{
		DriverBuildDir:       buildDir,
		KernelDownloadURLS:   urls,
		KernelLocalVersion:   kr.FullExtraversion,
		KernelHeadersPattern: "linux-headers*generic",
		GCCVersion:           ubuntuGCCVersionFromKernelRelease(kr),
	}

	if kr.IsGKE() {
		td.KernelHeadersPattern = "linux-headers*gke"
	}

	buf := bytes.NewBuffer(nil)
	err = parsed.Execute(buf, td)
	if err != nil {
		return "", err
	}
	return buf.String(), nil
}

// ubuntuAWS is a driverkit target.
type ubuntuAWS struct {
}

// Script compiles the script to build the kernel module and/or the eBPF probe.
func (v ubuntuAWS) Script(release string, buildDir string, kv uint16) (string, error) {
	t := template.New("ubuntu-aws-build-template")
	parsed, err := t.Parse(ubuntuTemplate)
	if err != nil {
		return "", err
	}

	kr := kernelrelease.FromString(release)

	urls, err := ubuntuAWSHeadersURLFromRelease(kr, kv)
	if len(urls) != 2 {
		return "", fmt.Errorf("specific kernel headers not found")
	}

	td := ubuntuTemplateData{
		DriverBuildDir:       buildDir,
		KernelDownloadURLS:   urls,
		KernelLocalVersion:   kr.FullExtraversion,
		KernelHeadersPattern: "linux-headers*",
		GCCVersion:           ubuntuGCCVersionFromKernelRelease(kr),
	}

	buf := bytes.NewBuffer(nil)
	err = parsed.Execute(buf, td)
	if err != nil {
		return "", err
	}
	return buf.String(), nil
}

func ubuntuAWSHeadersURLFromRelease(kr kernelrelease.KernelRelease, kv uint16) ([]string, error) {
	baseURL := []string{
		"https://mirrors.edge.kernel.org/ubuntu/pool/main/l/linux-aws",
		"http://security.ubuntu.com/ubuntu/pool/main/l/linux-aws",
	}

	for _, u := range baseURL {
		urls, err := getResolvingURLS(fetchUbuntuAWSKernelURLS(u, kr, kv))
		if err == nil {
			return urls, err
		}
	}

	// If we can't find the AWS files in the main folders,
	// try to proactively parse the subfolders to find what we need
	for _, u := range baseURL {
		url := fmt.Sprintf("%s-%s.%s", u, kr.Version, kr.PatchLevel)
		urls, err := parseUbuntuAWSKernelURLS(url, kr, kv)
		if err != nil {
			continue
		}
		urls, err = getResolvingURLS(urls)
		if err == nil {
			return urls, err
		}

	}

	return nil, fmt.Errorf("kernel headers not found")
}

func ubuntuGenericHeadersURLFromRelease(kr kernelrelease.KernelRelease, kv uint16) ([]string, error) {
	baseURL := []string{
		"https://mirrors.edge.kernel.org/ubuntu/pool/main/l/linux",
		"http://security.ubuntu.com/ubuntu/pool/main/l/linux",
		"https://mirrors.edge.kernel.org/ubuntu/pool/main/l/linux-gke-5.4",
		"https://mirrors.edge.kernel.org/ubuntu/pool/main/l/linux-gke-4.15",
	}

	for _, u := range baseURL {
		urls, err := getResolvingURLS(fetchUbuntuGenericKernelURL(u, kr, kv))
		if err == nil {
			return urls, err
		}
	}

	return nil, fmt.Errorf("kernel headers not found")
}

func fetchUbuntuGenericKernelURL(baseURL string, kr kernelrelease.KernelRelease, kernelVersion uint16) []string {
	firstExtra := extractExtraNumber(kr.Extraversion)
	if kr.IsGKE() {
		return []string{
			// For 4.15 GKE kernels
			fmt.Sprintf(
				"%s/linux-gke-%s.%s-headers-%s-%s_%s-%s.%d_amd64.deb",
				baseURL,
				kr.Version,
				kr.PatchLevel,
				kr.Fullversion,
				firstExtra,
				kr.Fullversion,
				firstExtra,
				kernelVersion,
			),
			fmt.Sprintf(
				"%s/linux-headers-%s%s_%s-%s.%d_amd64.deb",
				baseURL,
				kr.Fullversion,
				kr.FullExtraversion,
				kr.Fullversion,
				firstExtra,
				kernelVersion,
			),
			// For 5.4 GKE kernels
			fmt.Sprintf(
				"%s/linux-gke-%s.%s-headers-%s-%s_%s-%s.%d~18.04.1_amd64.deb",
				baseURL,
				kr.Version,
				kr.PatchLevel,
				kr.Fullversion,
				firstExtra,
				kr.Fullversion,
				firstExtra,
				kernelVersion,
			),
			fmt.Sprintf(
				"%s/linux-headers-%s%s_%s-%s.%d~18.04.1_amd64.deb",
				baseURL,
				kr.Fullversion,
				kr.FullExtraversion,
				kr.Fullversion,
				firstExtra,
				kernelVersion,
			),
		}
	}

	return []string{
		fmt.Sprintf(
			"%s/linux-headers-%s-%s_%s-%s.%d_all.deb",
			baseURL,
			kr.Fullversion,
			firstExtra,
			kr.Fullversion,
			firstExtra,
			kernelVersion,
		),
		fmt.Sprintf(
			"%s/linux-headers-%s-%s_%s-%s.%d_amd64.deb",
			baseURL,
			kr.Fullversion,
			kr.FullExtraversion,
			kr.Fullversion,
			firstExtra,
			kernelVersion,
		),
	}
}

func fetchUbuntuAWSKernelURLS(baseURL string, kr kernelrelease.KernelRelease, kernelVersion uint16) []string {
	firstExtra := extractExtraNumber(kr.Extraversion)
	return []string{
		fmt.Sprintf(
			"%s/linux-aws-headers-%s-%s_%s-%s.%d_all.deb",
			baseURL,
			kr.Fullversion,
			firstExtra,
			kr.Fullversion,
			firstExtra,
			kernelVersion,
		),
		fmt.Sprintf(
			"%s/linux-headers-%s%s_%s-%s.%d_amd64.deb",
			baseURL,
			kr.Fullversion,
			kr.FullExtraversion,
			kr.Fullversion,
			firstExtra,
			kernelVersion,
		),
	}
}

func parseUbuntuAWSKernelURLS(baseURL string, kr kernelrelease.KernelRelease, kv uint16) ([]string, error) {
	resp, err := http.Get(baseURL)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	body, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		return nil, err
	}
	firstExtra := extractExtraNumber(kr.Extraversion)
	rmatch := `href="(linux(?:-aws-%s.%s)?-headers-%s-%s(?:-aws)?_%s-%s\.%d.*(?:amd64|all)\.deb)"`
	fullRegex := fmt.Sprintf(rmatch, kr.Version, kr.PatchLevel, kr.Fullversion, firstExtra, kr.Fullversion, firstExtra, kv)
	pattern := regexp.MustCompile(fullRegex)
	matches := pattern.FindAllStringSubmatch(string(body), 2)
	if len(matches) != 2 {
		return nil, fmt.Errorf("kernel headers and kernel headers common not found")
	}

	foundURLs := []string{fmt.Sprintf("%s/%s", baseURL, matches[0][1])}
	foundURLs = append(foundURLs, fmt.Sprintf("%s/%s", baseURL, matches[1][1]))
	return foundURLs, nil
}

func extractExtraNumber(extraversion string) string {
	firstExtraSplit := strings.Split(extraversion, "-")
	if len(firstExtraSplit) > 0 {
		return firstExtraSplit[0]
	}
	return ""
}

type ubuntuTemplateData struct {
	DriverBuildDir       string
	KernelDownloadURLS   []string
	KernelLocalVersion   string
	KernelHeadersPattern string
	GCCVersion           string
}

const ubuntuTemplate = `
#!/bin/bash
set -xeuo pipefail

rm -rf /tmp/ubuntu-build
mkdir /tmp/ubuntu-build
cp -r {{ .DriverBuildDir }}/* /tmp/ubuntu-build/
cd /tmp/ubuntu-build

# Fetch the kernel
mkdir /tmp/kernel-download
cd /tmp/kernel-download
{{range $url := .KernelDownloadURLS}}
curl --silent -o kernel.deb -SL {{ $url }}
ar x kernel.deb
tar -xvf data.tar.*
{{end}}
ls -la /tmp/kernel-download

cd /tmp/kernel-download/usr/src/
sourcedir=$(find . -type d -name "{{ .KernelHeadersPattern }}" | head -n 1 | xargs readlink -f)

ls -la $sourcedir

# Change current gcc
ln -sf /usr/bin/gcc-{{ .GCCVersion }} /usr/bin/gcc

# Build the module
cd /tmp/ubuntu-build
make KBUILD_PATH=$sourcedir all
cp /tmp/ubuntu-build/chaos_driver.ko {{ .DriverBuildDir }}/chaos_driver.ko
`

func ubuntuGCCVersionFromKernelRelease(kr kernelrelease.KernelRelease) string {
	switch kr.Version {
	case "3":
		if kr.PatchLevel == "13" || kr.PatchLevel == "2" {
			return "4.8"
		}
		return "6"
	}
	return "8"
}
