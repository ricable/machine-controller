/*
Copyright 2019 The Machine Controller Authors.

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
*/

package helper

import (
	"encoding/json"
	"fmt"
	"strings"
	"text/template"

	"github.com/Masterminds/semver"

	"k8s.io/client-go/tools/clientcmd"
	clientcmdapi "k8s.io/client-go/tools/clientcmd/api"
)

func GetServerAddressFromKubeconfig(kubeconfig *clientcmdapi.Config) (string, error) {
	if len(kubeconfig.Clusters) != 1 {
		return "", fmt.Errorf("kubeconfig does not contain exactly one cluster, can not extract server address")
	}
	// Clusters is a map so we have to use range here
	for _, clusterConfig := range kubeconfig.Clusters {
		return strings.Replace(clusterConfig.Server, "https://", "", -1), nil
	}

	return "", fmt.Errorf("no server address found")

}

func GetCACert(kubeconfig *clientcmdapi.Config) (string, error) {
	if len(kubeconfig.Clusters) != 1 {
		return "", fmt.Errorf("kubeconfig does not contain exactly one cluster, can not extract server address")
	}
	// Clusters is a map so we have to use range here
	for _, clusterConfig := range kubeconfig.Clusters {
		return string(clusterConfig.CertificateAuthorityData), nil
	}

	return "", fmt.Errorf("no CACert found")
}

// StringifyKubeconfig marshals a kubeconfig to its text form
func StringifyKubeconfig(kubeconfig *clientcmdapi.Config) (string, error) {
	kubeconfigBytes, err := clientcmd.Write(*kubeconfig)
	if err != nil {
		return "", fmt.Errorf("error writing kubeconfig: %v", err)
	}

	return string(kubeconfigBytes), nil
}

// LoadKernelModules returns a script which is responsible for loading all required kernel modules
// The nf_conntrack_ipv4 module get removed in newer kernel versions
func LoadKernelModulesScript() string {
	return `#!/usr/bin/env bash
set -euo pipefail

modprobe ip_vs
modprobe ip_vs_rr
modprobe ip_vs_wrr
modprobe ip_vs_sh

if modinfo nf_conntrack_ipv4 &> /dev/null; then
  modprobe nf_conntrack_ipv4
else
  modprobe nf_conntrack
fi
`
}

// KernelSettings returns the list of kernel settings required for a kubernetes worker node
// inotify changes according to https://github.com/kubernetes/kubernetes/issues/10421 - better than letting the kubelet die
func KernelSettings() string {
	return `net.bridge.bridge-nf-call-ip6tables = 1
net.bridge.bridge-nf-call-iptables = 1
kernel.panic_on_oops = 1
kernel.panic = 10
net.ipv4.ip_forward = 1
vm.overcommit_memory = 1
fs.inotify.max_user_watches = 1048576
`
}

// JournalDConfig returns the journal config preferable on every node
func JournalDConfig() string {
	// JournaldMaxUse defines the maximum space that journalD logs can occupy.
	// https://www.freedesktop.org/software/systemd/man/journald.conf.html#SystemMaxUse=
	return `[Journal]
SystemMaxUse=5G
`
}

type dockerConfig struct {
	ExecOpts           []string          `json:"exec-opts,omitempty"`
	StorageDriver      string            `json:"storage-driver,omitempty"`
	StorageOpts        []string          `json:"storage-opts,omitempty"`
	LogDriver          string            `json:"log-driver,omitempty"`
	LogOpts            map[string]string `json:"log-opts,omitempty"`
	InsecureRegistries []string          `json:"insecure-registries,omitempty"`
	RegistryMirrors    []string          `json:"registry-mirrors,omitempty"`
}

var (
	dockerCEYumTemplate = template.Must(template.New("docker-ce-yum").Parse(`
yum install -y yum-utils
yum-config-manager --add-repo=https://download.docker.com/linux/centos/docker-ce.repo
{{- /*
	Due to DNF modules we have to do this on docker-ce repo
	More info at: https://bugzilla.redhat.com/show_bug.cgi?id=1756473
*/}}
yum-config-manager --save --setopt=docker-ce-stable.module_hotfixes=true

DOCKER_VERSION='{{ .DockerVersion }}'

mkdir -p /etc/systemd/system/docker.service.d
cat <<EOF | tee /etc/systemd/system/docker.service.d/environment.conf
[Service]
Restart=always
EnvironmentFile=-/etc/environment
EOF

yum install -y \
    docker-ce-${DOCKER_VERSION} docker-ce-cli-${DOCKER_VERSION} \
    yum-plugin-versionlock
yum versionlock add docker-ce-*
systemctl enable --now docker
`))

	dockerCEAptTemplate = template.Must(template.New("docker-ce-apt").Parse(`
apt-get update
apt-get install -y apt-transport-https ca-certificates curl software-properties-common lsb-release
curl -fsSL https://download.docker.com/linux/ubuntu/gpg | apt-key add -
add-apt-repository "deb https://download.docker.com/linux/ubuntu $(lsb_release -cs) stable"

mkdir -p /etc/systemd/system/docker.service.d
cat <<EOF | tee /etc/systemd/system/docker.service.d/environment.conf
[Service]
Restart=always
EnvironmentFile=-/etc/environment
EOF

apt-get update
apt-get install -y \
    containerd.io=1.2.13-2 \
    docker-ce=5:19.03.11~3-0~ubuntu-$(lsb_release -cs) \
    docker-ce-cli=5:19.03.11~3-0~ubuntu-$(lsb_release -cs)
`))

	containerdYumTemplate = template.Must(template.New("containerd-yum").Parse(`
yum install -y yum-utils
yum-config-manager --add-repo=https://download.docker.com/linux/centos/docker-ce.repo
{{- /*
	Due to DNF modules we have to do this on docker-ce repo
	More info at: https://bugzilla.redhat.com/show_bug.cgi?id=1756473
*/}}
yum-config-manager --save --setopt=docker-ce-stable.module_hotfixes=true
yum install -y containerd.io-1.2.13 yum-plugin-versionlock
yum versionlock add containerd.io

mkdir -p /etc/containerd
containerd config default | sed -e 's/systemd_cgroup = false/systemd_cgroup = true/' > /etc/containerd/config.toml

mkdir -p /etc/systemd/system/containerd.service.d
cat <<EOF | tee /etc/systemd/system/containerd.service.d/environment.conf
[Service]
Restart=always
EnvironmentFile=-/etc/environment
EOF

systemctl daemon-reload
systemctl enable --now containerd
`))

	containerdAptTemplate = template.Must(template.New("containerd-apt").Parse(`
apt-get update
apt-get install -y apt-transport-https ca-certificates curl software-properties-common lsb-release
curl -fsSL https://download.docker.com/linux/ubuntu/gpg | apt-key add -
add-apt-repository "deb https://download.docker.com/linux/ubuntu $(lsb_release -cs) stable"
apt-get install -y containerd.io=1.2.13-2

mkdir -p /etc/containerd
containerd config default | sed -e 's/systemd_cgroup = false/systemd_cgroup = true/' > /etc/containerd/config.toml

mkdir -p /etc/systemd/system/containerd.service.d
cat <<EOF | tee /etc/systemd/system/containerd.service.d/environment.conf
[Service]
Restart=always
EnvironmentFile=-/etc/environment
EOF

systemctl daemon-reload
systemctl enable --now containerd
`))
)

func InstallContainerRuntimeScript(packageManager, cr, kubeletVersion string) (string, error) {
	var buf strings.Builder

	switch fmt.Sprintf("%s %s", cr, packageManager) {
	case "docker-ce apt":
		return buf.String(), dockerCEAptTemplate.Execute(&buf, nil)
	case "docker-ce yum":
		return buf.String(), dockerCEYumTemplate.Execute(&buf, nil)
	case "containerd apt":
		return buf.String(), containerdAptTemplate.Execute(&buf, nil)
	case "containerd yum":
		return buf.String(), containerdYumTemplate.Execute(&buf, nil)
	}

	return "", fmt.Errorf("container runtime: %s / package manager: %s are not a supported", cr, packageManager)
}

// DockerConfig returns the docker daemon.json.
func DockerConfig(insecureRegistries, registryMirrors []string) (string, error) {
	cfg := dockerConfig{
		ExecOpts:           []string{"native.cgroupdriver=systemd"},
		StorageDriver:      "overlay2",
		LogDriver:          "json-file",
		LogOpts:            map[string]string{"max-size": "100m"},
		InsecureRegistries: insecureRegistries,
		RegistryMirrors:    registryMirrors,
	}
	if insecureRegistries == nil {
		cfg.InsecureRegistries = []string{}
	}
	if registryMirrors == nil {
		cfg.RegistryMirrors = []string{}
	}

	b, err := json.Marshal(cfg)
	return string(b), err
}

// DockerVersionApt returns Docker version to be installed on instances using apt (Ubuntu).
func DockerVersionApt(kubernetesVersion *semver.Version) (string, error) {
	if kubernetesVersion == nil {
		return "", fmt.Errorf("invalid kubernetes version")
	}

	lessThen117, _ := semver.NewConstraint("< 1.17")

	if lessThen117.Check(kubernetesVersion) {
		return "5:18.09.9~3-0~ubuntu-bionic", nil
	}

	// return default
	return "5:19.03.12~3-0~ubuntu-bionic", nil
}

// DockerVersionYum returns Docker version to be installed on instances using yum (CentOS/RHEL).
func DockerVersionYum(kubernetesVersion *semver.Version) (string, error) {
	if kubernetesVersion == nil {
		return "", fmt.Errorf("invalid kubernetes version")
	}

	lessThen117, _ := semver.NewConstraint("< 1.17")

	if lessThen117.Check(kubernetesVersion) {
		return "18.09.9-3.el7", nil
	}

	// return default
	return "19.03.12-3.el7", nil
}

func ProxyEnvironment(proxy, noProxy string) string {
	return fmt.Sprintf(`HTTP_PROXY=%s
http_proxy=%s
HTTPS_PROXY=%s
https_proxy=%s
NO_PROXY=%s
no_proxy=%s`, proxy, proxy, proxy, proxy, noProxy, noProxy)
}

func SetupNodeIPEnvScript() string {
	return `#!/usr/bin/env bash
echodate() {
  echo "[$(date -Is)]" "$@"
}

# get the default interface IP address
DEFAULT_IFC_IP=$(ip -o  route get 1 | grep -oP "src \K\S+")

if [ -z "${DEFAULT_IFC_IP}" ]
then
	echodate "Failed to get IP address for the default route interface"
	exit 1
fi

# write the nodeip_env file
if grep -q coreos /etc/os-release
then
  echo "KUBELET_NODE_IP=${DEFAULT_IFC_IP}" > /etc/kubernetes/nodeip.conf
elif [ ! -d /etc/systemd/system/kubelet.service.d ]
then
	echodate "Can't find kubelet service extras directory"
	exit 1
else
  echo -e "[Service]\nEnvironment=\"KUBELET_NODE_IP=${DEFAULT_IFC_IP}\"" > /etc/systemd/system/kubelet.service.d/nodeip.conf
fi
	`
}

// ContainerRuntime zero-vaulue equals to ContainerRuntimeDockerCE
type ContainerRuntime int

const (
	ContainerRuntimeDockerCE ContainerRuntime = iota
	ContainerRuntimeContainerd
)

var (
	stringToContainerRuntimeMap = map[string]ContainerRuntime{
		"docker-ce":  ContainerRuntimeDockerCE,
		"containerd": ContainerRuntimeContainerd,
	}
)

func (cr ContainerRuntime) String() string {
	for k, v := range stringToContainerRuntimeMap {
		if v == cr {
			return k
		}
	}

	return "docker-ce"
}

func GetContainerRuntime(containerRuntime string) ContainerRuntime {
	return stringToContainerRuntimeMap[containerRuntime]
}
