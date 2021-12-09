package build

import (
	"bytes"
	"fmt"
	"text/template"

	"github.com/chaos-mesh/chaos-driver/buildkit/build/kernelrelease"
)

type CentosBuilder struct {
}

func (b *CentosBuilder) Script(release string, buildDir string, _ uint16) (string, error) {
	kr := kernelrelease.FromString(release)
	urls, err := getResolvingURLS(fetchCentosKernelURLS(kr))
	if err != nil {
		return "", err
	}

	td := centosTemplateData{
		DriverBuildDir:    buildDir,
		KernelDownloadURL: urls[0],
		GCCVersion:        centosGccVersionFromKernelRelease(kr),
	}

	buf := bytes.NewBuffer(nil)
	t := template.New("centos-build-template")
	parsed, err := t.Parse(centosTemplate)
	if err != nil {
		return "", err
	}

	err = parsed.Execute(buf, td)
	if err != nil {
		return "", err
	}
	return buf.String(), nil
}

func fetchCentosKernelURLS(kr kernelrelease.KernelRelease) []string {
	vaultReleases := []string{
		"6.0/os",
		"6.0/updates",
		"6.1/os",
		"6.1/updates",
		"6.2/os",
		"6.2/updates",
		"6.3/os",
		"6.3/updates",
		"6.4/os",
		"6.4/updates",
		"6.5/os",
		"6.5/updates",
		"6.6/os",
		"6.6/updates",
		"6.7/os",
		"6.7/updates",
		"6.8/os",
		"6.8/updates",
		"6.9/os",
		"6.9/updates",
		"6.10/os",
		"6.10/updates",
		"7.0.1406/os",
		"7.0.1406/updates",
		"7.1.1503/os",
		"7.1.1503/updates",
		"7.2.1511/os",
		"7.2.1511/updates",
		"7.3.1611/os",
		"7.3.1611/updates",
		"7.4.1708/os",
		"7.4.1708/updates",
		"7.5.1804/os",
		"7.5.1804/updates",
		"7.6.1810/os",
		"7.6.1810/updates",
		"7.7.1908/os",
		"7.7.1908/updates",
		"7.8.2003/os",
		"7.8.2003/updates",
		"7.9.2009/os",
		"7.9.2009/updates",
		"8.0.1905/os",
		"8.0.1905/updates",
		"8.1.1911/os",
		"8.1.1911/updates",
	}

	edgeReleases := []string{
		"6/os",
		"6/updates",
		"7/os",
		"7/updates",
	}

	streamReleases := []string{
		"8/BaseOS",
		"8-stream/BaseOS",
		"8.0.1905/BaseOS",
		"8.1.1911/BaseOS",
	}

	urls := []string{}
	for _, r := range edgeReleases {
		urls = append(urls, fmt.Sprintf(
			"https://mirrors.edge.kernel.org/centos/%s/x86_64/Packages/kernel-devel-%s-%s%s.rpm",
			r,
			kr.Fullversion,
			kr.Extraversion,
			kr.Tail,
		))
	}
	for _, r := range streamReleases {
		urls = append(urls, fmt.Sprintf(
			"https://mirrors.edge.kernel.org/centos/%s/x86_64/os/Packages/kernel-devel-%s-%s%s.rpm",
			r,
			kr.Fullversion,
			kr.Extraversion,
			kr.Tail,
		))
	}
	for _, r := range vaultReleases {
		urls = append(urls, fmt.Sprintf(
			"http://vault.centos.org/%s/x86_64/Packages/kernel-devel-%s-%s%s.rpm",
			r,
			kr.Fullversion,
			kr.Extraversion,
			kr.Tail,
		))
	}
	return urls
}

type centosTemplateData struct {
	DriverBuildDir    string
	KernelDownloadURL string
	GCCVersion        string
}

const centosTemplate = `
#!/bin/bash
set -xeuo pipefail

rm -rf /tmp/centos-build
mkdir /tmp/centos-build
cp -r {{ .DriverBuildDir }}/* /tmp/centos-build/
cd /tmp/centos-build

curl --silent -o kernel-devel.rpm -SL {{ .KernelDownloadURL }}
rpm2cpio kernel-devel.rpm | cpio --extract --make-directories
rm -Rf /tmp/kernel
mkdir -p /tmp/kernel
mv usr/src/kernels/*/* /tmp/kernel

# Change current gcc
ln -sf /usr/bin/gcc-{{ .GCCVersion }} /usr/bin/gcc

# Build the kernel module
make KBUILD_PATH=/tmp/kernel all
cp /tmp/centos-build/chaos_driver.ko {{ .DriverBuildDir }}/chaos_driver.ko
`

func centosGccVersionFromKernelRelease(kr kernelrelease.KernelRelease) string {
	switch kr.Version {
	case "3":
		return "5"
	case "2":
		return "4.8"
	}
	return "8"
}

func init() {
	Targets["centos"] = &CentosBuilder{}
}
