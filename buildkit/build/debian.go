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
	Targets["debian"] = &debian{}
}

// debian is a driverkit target.
type debian struct {
}

// Script compiles the script to build the kernel module and/or the eBPF probe.
func (v debian) Script(release string, buildDir string, _ uint16) (string, error) {
	t := template.New("debian-build-template")
	parsed, err := t.Parse(debianTemplate)
	if err != nil {
		return "", err
	}

	kr := kernelrelease.FromString(release)

	kurls, err := fetchDebianKernelURLS(kr)
	if err != nil {
		return "", err
	}

	urls, err := getResolvingURLS(kurls)
	if err != nil {
		return "", err
	}

	td := debianTemplateData{
		DriverBuildDir:     buildDir,
		KernelDownloadURLS: urls,
		KernelLocalVersion: kr.FullExtraversion,
	}

	buf := bytes.NewBuffer(nil)
	err = parsed.Execute(buf, td)
	if err != nil {
		return "", err
	}
	return buf.String(), nil
}

func fetchDebianKernelURLS(kr kernelrelease.KernelRelease) ([]string, error) {
	kbuildURL, err := debianKbuildURLFromRelease(kr)
	if err != nil {
		return nil, err
	}

	urls, err := debianHeadersURLFromRelease(kr)
	if err != nil {
		return nil, err
	}
	urls = append(urls, kbuildURL)

	return urls, nil
}

type debianTemplateData struct {
	DriverBuildDir     string
	KernelDownloadURLS []string
	KernelLocalVersion string
}

const debianTemplate = `
#!/bin/bash
set -xeuo pipefail

rm -rf /tmp/debian-build
mkdir /tmp/debian-build
cp -r {{ .DriverBuildDir }}/* /tmp/debian-build/
cd /tmp/debian-build

# Fetch the kernel
mkdir /tmp/kernel-download
cd /tmp/kernel-download

{{ range $url := .KernelDownloadURLS }}
curl --silent -o kernel.deb -SL {{ $url }}
ar x kernel.deb
tar -xvf data.tar.xz
{{ end }}

ls -la /tmp/kernel-download
cd /tmp/kernel-download/
cp -r usr/* /usr
cp -r lib/* /lib
cd /usr/src
sourcedir=$(find . -type d -name "linux-headers-*amd64" | head -n 1 | xargs readlink -f)
ls -la $sourcedir

cd /tmp/debian-build

# Build the kernel module
make KBUILD_PATH=$sourcedir all
cp /tmp/debian-build/chaos_driver.ko {{ .DriverBuildDir }}/chaos_driver.ko
`

func debianHeadersURLFromRelease(kr kernelrelease.KernelRelease) ([]string, error) {
	baseURLS := []string{
		"http://security-cdn.debian.org/pool/main/l/linux/",
		"http://security-cdn.debian.org/pool/updates/main/l/linux/",
		"https://mirrors.edge.kernel.org/debian/pool/main/l/linux/",
	}

	for _, u := range baseURLS {
		urls, err := fetchDebianHeadersURLFromRelease(u, kr)

		if err == nil {
			return urls, err
		}
	}

	return nil, fmt.Errorf("kernel headers not found")
}

func fetchDebianHeadersURLFromRelease(baseURL string, kr kernelrelease.KernelRelease) ([]string, error) {
	rmatch := `href="(linux-headers-%s\.%s\.%s-%s-(%s)_.*(amd64|all)\.deb)"`

	// match for kernel versions like 4.19.0-6-amd64
	extraVersionPartial := strings.TrimSuffix(kr.FullExtraversion, "-amd64")
	matchExtraGroup := "amd64"
	matchExtraGroupCommon := "common"

	// match for kernel versions like 4.19.0-6-cloud-amd64
	if strings.Contains(kr.FullExtraversion, "-cloud") {
		extraVersionPartial = strings.TrimSuffix(extraVersionPartial, "-cloud")
		matchExtraGroup = "cloud-amd64"
	}

	// download index
	resp, err := http.Get(baseURL)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	body, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		return nil, err
	}
	bodyStr := string(body)

	// look for kernel headers
	fullregex := fmt.Sprintf(rmatch, kr.Version, kr.PatchLevel, kr.Sublevel, extraVersionPartial, matchExtraGroup)
	pattern := regexp.MustCompile(fullregex)
	matches := pattern.FindStringSubmatch(bodyStr)
	if len(matches) < 1 {
		return nil, fmt.Errorf("kernel headers not found")
	}

	// look for kernel headers common
	fullregexCommon := fmt.Sprintf(rmatch, kr.Version, kr.PatchLevel, kr.Sublevel, extraVersionPartial, matchExtraGroupCommon)
	patternCommon := regexp.MustCompile(fullregexCommon)
	matchesCommon := patternCommon.FindStringSubmatch(bodyStr)
	if len(matchesCommon) < 1 {
		return nil, fmt.Errorf("kernel headers common not found")
	}

	foundURLS := []string{fmt.Sprintf("%s%s", baseURL, matches[1])}
	foundURLS = append(foundURLS, fmt.Sprintf("%s%s", baseURL, matchesCommon[1]))

	return foundURLS, nil
}

func debianKbuildURLFromRelease(kr kernelrelease.KernelRelease) (string, error) {
	rmatch := `href="(linux-kbuild-%s\.%s.*amd64\.deb)"`
	kbuildPattern := regexp.MustCompile(fmt.Sprintf(rmatch, kr.Version, kr.PatchLevel))
	baseURL := "http://mirrors.kernel.org/debian/pool/main/l/linux/"
	if kr.Version == "3" {
		baseURL = "http://mirrors.kernel.org/debian/pool/main/l/linux-tools/"
	}

	resp, err := http.Get(baseURL)
	if err != nil {
		return "", err
	}
	defer resp.Body.Close()
	body, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		return "", err
	}
	match := kbuildPattern.FindStringSubmatch(string(body))

	if len(match) != 2 {
		return "", fmt.Errorf("kbuild not found")
	}

	return fmt.Sprintf("%s%s", baseURL, match[1]), nil
}
