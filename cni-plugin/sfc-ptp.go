// Copyright 2017 CNI authors
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

// This is a sample chained plugin that supports multiple CNI versions. It
// parses prevResult according to the cniVersion
package main

import (
	"context"
	"crypto/sha1"
	"encoding/json"
	"errors"
	"fmt"
	"log"
	"os"
	"path/filepath"
	"runtime"
	"strconv"

	"github.com/vishvananda/netlink"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/tools/clientcmd"
	"k8s.io/client-go/util/retry"

	"github.com/containernetworking/cni/pkg/skel"
	"github.com/containernetworking/cni/pkg/types"
	current "github.com/containernetworking/cni/pkg/types/100"
	"github.com/containernetworking/cni/pkg/version"
	"github.com/containernetworking/plugins/pkg/ip"
	"github.com/containernetworking/plugins/pkg/ipam"
	"github.com/containernetworking/plugins/pkg/ns"

	// "github.com/containernetworking/plugins/pkg/utils"
	"github.com/containernetworking/plugins/plugins/ipam/host-local/backend/disk"

	bv "github.com/containernetworking/plugins/pkg/utils/buildversion"
)

var LOG_FILE string = "/tmp/sfc-ptp.log"

func init() {
	// this ensures that main runs only on main thread (thread group leader).
	// since namespace ops (unshare, setns) are done for a single thread, we
	// must ensure that the goroutine does not jump from OS thread to thread
	runtime.LockOSThread()
}

type PluginConf struct {
	// This embeds the standard NetConf structure which allows plugin
	// to more easily parse standard fields like Name, Type, CNIVersion,
	// and PrevResult.
	types.NetConf

	// Add plugin-specifc flags here
	DataDir             string `json:"dataDir"`
	HostInterfacePrefix string `json:"hostInterfacePrefix"`
	MacGenerationString string `json:"macGenerationString"`
	MTU                 int    `json:"mtu"`
	Kubeconfig          string `json:"kubeconfig"`
}

type K8sArgs struct {
	types.CommonArgs
	K8S_POD_NAME               types.UnmarshallableString
	K8S_POD_NAMESPACE          types.UnmarshallableString
	K8S_POD_INFRA_CONTAINER_ID types.UnmarshallableString
	K8S_POD_UID                types.UnmarshallableString
}

// Default Multus Kubeconfig file path
var defaultKubeconfigPath string = "/etc/cni/net.d/multus.d/multus.kubeconfig"

// Default value for DataDir where are stored index for interfaces
var defaultDataDir string = "/var/lib/cni/interfaces"

// MAC prefix that will be combined with hashed value
var macPrefix string = "0E:00:00"

// Network Namespace annotation
var linkAnnotation string = "servicefunctionchain.polito.it/host-link"

// parseArgs parses the supplied K8sArgs
func parseK8sArgs(args string) (*K8sArgs, error) {
	k8sArgs := &K8sArgs{}
	err := types.LoadArgs(args, k8sArgs)
	if err != nil {
		return nil, err
	}

	return k8sArgs, nil
}

// parseConfig parses the supplied configuration from stdin.
func parseConfig(stdin []byte) (*PluginConf, error) {
	conf := PluginConf{}

	if err := json.Unmarshal(stdin, &conf); err != nil {
		return nil, fmt.Errorf("failed to parse network configuration: %v", err)
	}

	// Validation
	if conf.MacGenerationString == "" {
		return nil, fmt.Errorf("macGenerationString must be specified")
	}

	if conf.Kubeconfig == "" {
		conf.Kubeconfig = defaultKubeconfigPath
	}

	return &conf, nil
}

// Hash given string and return an hex string
func hashString(s string) string {
	hashValue := sha1.Sum([]byte(s))
	return fmt.Sprintf("%x", hashValue)
}

func createHostVethName(hostInterfacePrefix string, dataDir string) (string, error) {
	// Check if a hostInterfacePrefix has been specified
	if hostInterfacePrefix == "" {
		return "", nil
	}
	// Check if a custom DataDir has been specified
	if dataDir == "" {
		// Use default DataDir
		dataDir = defaultDataDir
	}

	// Get path for the handled interface prefix
	// and create all necessary folders
	dir := filepath.Join(dataDir, hostInterfacePrefix)
	if err := os.MkdirAll(dir, 0755); err != nil {
		return "", err
	}

	// Create file lock
	lk, err := disk.NewFileLock(dir)
	if err != nil {
		return "", err
	}

	// Acquire lock on file lock to avoid interference between
	// simultaneous plugin calls
	lk.Lock()
	defer lk.Unlock()

	// Read last index for this host interface name from file
	var index int
	indexFilePath := filepath.Join(dir, "index")
	data, err := os.ReadFile(indexFilePath)
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			// File doesn't exist yet, use 0 as index
			index = 0
		} else {
			// Generic error
			return "", err
		}
	} else {
		// File exist, get last used index
		index, err = strconv.Atoi(string(data))
		if err != nil {
			return "", nil
		}
	}

	// Open file to update last used index
	indexFile, err := os.OpenFile(indexFilePath, os.O_WRONLY|os.O_CREATE|os.O_TRUNC, 0644)
	if err != nil {
		return "", err
	}

	// Write new last used index
	index += 1
	_, err = indexFile.WriteString(strconv.Itoa(index))
	if err != nil {
		return "", nil
	}

	// Return host veth name (hostInterfacePrefix-{index})
	return hostInterfacePrefix + "-" + strconv.Itoa(index), nil
}

func createPodVethMac(macGenerationString string) string {
	// Hash macGenerationString to make a MAC suffix
	hash := hashString(macGenerationString)
	return fmt.Sprintf("%s:%s:%s:%s", macPrefix, hash[:2], hash[2:4], hash[4:6])
}

func setupL2Veth(netns ns.NetNS, ifName string, hostIfname string, hostInterfacePrefix string, mtu int, mac string) (*current.Interface, *current.Interface, error) {
	hostInterface := &current.Interface{}
	podInterface := &current.Interface{}

	err := netns.Do(func(hostNS ns.NetNS) error {
		hostVeth, contVeth0, err := ip.SetupVethWithName(ifName, hostIfname, mtu, mac, hostNS)
		if err != nil {
			return err
		}

		hostInterface.Name = hostVeth.Name
		hostInterface.Mac = hostVeth.HardwareAddr.String()
		podInterface.Name = contVeth0.Name
		podInterface.Mac = contVeth0.HardwareAddr.String()
		podInterface.Sandbox = netns.Path()

		return nil
	})
	if err != nil {
		return nil, nil, err
	}
	return hostInterface, podInterface, nil
}

func setupL3Veth(netns ns.NetNS, ifName string, hostIfname string, hostInterfacePrefix string, mtu int, mac string, pr *current.Result) (*current.Interface, *current.Interface, error) {
	hostInterface := &current.Interface{}
	podInterface := &current.Interface{}

	err := netns.Do(func(hostNS ns.NetNS) error {
		hostVeth, contVeth0, err := ip.SetupVethWithName(ifName, hostIfname, mtu, mac, hostNS)
		if err != nil {
			return err
		}

		hostInterface.Name = hostVeth.Name
		hostInterface.Mac = hostVeth.HardwareAddr.String()
		podInterface.Name = contVeth0.Name
		podInterface.Mac = contVeth0.HardwareAddr.String()
		podInterface.Sandbox = netns.Path()

		for _, ipc := range pr.IPs {
			// All addresses apply to the pod veth interface
			ipc.Interface = current.Int(1)
		}

		pr.Interfaces = []*current.Interface{hostInterface, podInterface}

		// Configure pod veth with given IPAM configuration
		if err = ipam.ConfigureIface(ifName, pr); err != nil {
			return err
		}

		return nil
	})
	if err != nil {
		return nil, nil, err
	}
	return hostInterface, podInterface, nil
}

func setPodInterfaceUp(netns ns.NetNS, ifname string) error {
	// Set pod interface up (explicit call needed on L2 mode only)
	if err := netns.Do(func(_ ns.NetNS) error {
		link, err := netlink.LinkByName(ifname)
		if err != nil {
			return err
		}
		// Set pod veth UP
		if err = netlink.LinkSetUp(link); err != nil {
			return err
		}
		return nil
	}); err != nil {
		return err
	}
	return nil
}

func setPodNetworkInterface(kubeconfigPath string, ifName string, hostIfname string, k8sArgs *K8sArgs) error {
	// Get host link
	hostLink, err := netlink.LinkByName(hostIfname)
	if err != nil {
		return err
	}
	// Get link index
	index := hostLink.Attrs().Index

	// Create Kubernetes client to interact with the API server
	restClientConfig, err := clientcmd.BuildConfigFromFlags("", kubeconfigPath)
	if err != nil {
		return err
	}
	clientset, err := kubernetes.NewForConfig(restClientConfig)
	if err != nil {
		return err
	}
	coreClient := clientset.CoreV1()

	// TODO: check the UID match?
	// Get details about the current Pod
	name := string(k8sArgs.K8S_POD_NAME)
	namespace := string(k8sArgs.K8S_POD_NAMESPACE)

	// Set the network interface annotation
	resultErr := retry.RetryOnConflict(retry.DefaultRetry, func() error {
		// Get Pod object from the API server
		pod, err := clientset.CoreV1().Pods(namespace).Get(context.TODO(), name, metav1.GetOptions{})
		if err != nil {
			return err
		}
		// Create link map [podIfname] -> hostIfindex
		linkMap := map[string]string{}

		// Check if pod has annotations map
		if len(pod.Annotations) == 0 {
			pod.Annotations = make(map[string]string)
		}
		// Check if pod has host-link annotation already
		_, ok := pod.Annotations[linkAnnotation]
		if ok {
			err = json.Unmarshal([]byte(pod.Annotations[linkAnnotation]), &linkMap)
			if err != nil {
				return err
			}
		}
		// Add link to map
		linkMap[ifName] = strconv.Itoa(index)
		// Marshal map to JSON
		jsonData, err := json.Marshal(linkMap)
		if err != nil {
			return err
		}

		// Try to add annotation
		pod.Annotations[linkAnnotation] = string(jsonData)
		_, err = coreClient.Pods(namespace).UpdateStatus(context.TODO(), pod, metav1.UpdateOptions{})
		return err
	})
	if resultErr != nil {
		return resultErr
	}

	return nil
}

// cmdAdd is called for ADD requests
func cmdAdd(args *skel.CmdArgs) error {
	// Open log file
	logFile, err := os.OpenFile(LOG_FILE, os.O_APPEND|os.O_RDWR|os.O_CREATE, 0644)
	if err != nil {
		return err
	}
	defer logFile.Close()
	// Setup log output
	log.SetOutput(logFile)
	log.SetFlags(log.Ldate | log.LUTC | log.Ltime | log.Lmicroseconds | log.Lmsgprefix)
	log.SetPrefix("[ ADD ] ")
	log.Println("Executing ADD")

	// Parse K8sArgs
	k8sArgs, err := parseK8sArgs(args.Args)
	if err != nil {
		log.Printf("Failed to parse K8sArgs: %v", err)
		return err
	}

	// Update log prefix with Pod name
	logPrefix := fmt.Sprintf("[ ADD ] [ %s ] ", k8sArgs.K8S_POD_NAME)
	log.SetPrefix(logPrefix)

	// Parse configuration from stdin
	conf, err := parseConfig(args.StdinData)
	if err != nil {
		log.Printf("Failed to parse config: %v", err)
		return err
	}

	// Create host veth name from the prefix (add a progressive index)
	hostVethName, err := createHostVethName(conf.HostInterfacePrefix, conf.DataDir)
	if err != nil {
		log.Printf("Failed to create Host veth name: %v", err)
		return err
	}

	// Create pod veth address from the given string
	podVethMac := createPodVethMac(conf.MacGenerationString)
	if err != nil {
		log.Printf("Failed to create pod veth MAC: %v", err)
		return err
	}

	// Check if IPAM configuration is required
	isLayer3 := conf.IPAM.Type != ""

	var result *current.Result
	var hostInterface *current.Interface

	if isLayer3 {
		// Run the IPAM plugin and get back the config to apply
		r, err := ipam.ExecAdd(conf.IPAM.Type, args.StdinData)
		if err != nil {
			log.Printf("ipam.ExecAdd returned error: %v", err)
			return err
		}

		// Invoke ipam del if err to avoid ip leak
		defer func() {
			if err != nil && isLayer3 {
				ipam.ExecDel(conf.IPAM.Type, args.StdinData)
			}
		}()

		// Convert whatever the IPAM result was into the current Result type
		result, err = current.NewResultFromResult(r)
		if err != nil {
			log.Printf("Failed to convert result from IPAM: %v", err)
			return err
		}

		if len(result.IPs) == 0 {
			log.Printf("IPAM plugin returned missing IP config")
			return errors.New("IPAM plugin returned missing IP config")
		}

		// if err := ip.EnableForward(result.IPs); err != nil {
		// 	return fmt.Errorf("Could not enable IP forwarding: %v", err)
		// }

		netns, err := ns.GetNS(args.Netns)
		if err != nil {
			log.Printf("Failed to open netns %q: %v", args.Netns, err)
			return fmt.Errorf("failed to open netns %q: %v", args.Netns, err)
		}
		defer netns.Close()

		// Setup L3 veth
		hostInterface, _, err = setupL3Veth(netns, args.IfName, hostVethName, conf.HostInterfacePrefix, conf.MTU, podVethMac, result)
		if err != nil {
			log.Printf("Failed to setup L3 veth: %v", err)
			return err
		}

	} else {
		// Layer 2 only

		netns, err := ns.GetNS(args.Netns)
		if err != nil {
			log.Printf("Failed to open netns %q: %v", args.Netns, err)
			return fmt.Errorf("failed to open netns %q: %v", args.Netns, err)
		}
		defer netns.Close()

		// Setup L2 veth
		var podInterface *current.Interface
		hostInterface, podInterface, err = setupL2Veth(netns, args.IfName, hostVethName, conf.HostInterfacePrefix, conf.MTU, podVethMac)
		if err != nil {
			log.Printf("Failed to setup L2 veth: %v", err)
			return err
		}

		// Setup pod interface up
		err = setPodInterfaceUp(netns, args.IfName)
		if err != nil {
			log.Printf("Failed to set pod interface up: %v", err)
			return err
		}

		result = &current.Result{
			CNIVersion: current.ImplementedSpecVersion,
			Interfaces: []*current.Interface{
				hostInterface,
				podInterface,
			},
		}
	}

	// Only override the DNS settings in the previous result if any DNS fields
	// were provided to the sfc-ptp plugin. This allows, for example, IPAM plugins
	// to specify the DNS settings instead of the sfc-ptp plugin.
	if dnsConfSet(conf.DNS) {
		result.DNS = conf.DNS
	}

	// Set Pod Network Interface
	err = setPodNetworkInterface(conf.Kubeconfig, args.IfName, hostInterface.Name, k8sArgs)
	if err != nil {
		log.Printf("Failed to set the Pod Network Interface: %v", err)
		return err
	}

	log.Println("sfc-ptp plugin ran successfully")
	// Return result
	return types.PrintResult(result, conf.CNIVersion)
}

func dnsConfSet(dnsConf types.DNS) bool {
	return dnsConf.Nameservers != nil ||
		dnsConf.Search != nil ||
		dnsConf.Options != nil ||
		dnsConf.Domain != ""
}

// cmdDel is called for DELETE requests
func cmdDel(args *skel.CmdArgs) error {
	// Open log file
	logFile, err := os.OpenFile(LOG_FILE, os.O_APPEND|os.O_RDWR|os.O_CREATE, 0644)
	if err != nil {
		return err
	}
	defer logFile.Close()
	// Setup log output
	log.SetOutput(logFile)
	log.SetFlags(log.Ldate | log.LUTC | log.Ltime | log.Lmicroseconds | log.Lmsgprefix)
	log.SetPrefix("[ DEL ] ")
	log.Println("Executing DEL")

	// Parse K8sArgs
	k8sArgs, err := parseK8sArgs(args.Args)
	if err != nil {
		log.Printf("Failed to parse K8sArgs: %v", err)
		return err
	}

	// Update log prefix with Pod name
	logPrefix := fmt.Sprintf("[ DEL ] [ %s ] ", k8sArgs.K8S_POD_NAME)
	log.SetPrefix(logPrefix)

	// Parse configuration from stdin
	conf, err := parseConfig(args.StdinData)
	if err != nil {
		log.Printf("Failed to parse config: %v", err)
		return err
	}

	// Check if IPAM clean up is required
	isLayer3 := conf.IPAM.Type != ""

	if isLayer3 {
		if err := ipam.ExecDel(conf.IPAM.Type, args.StdinData); err != nil {
			log.Printf("ipam.ExecDel returned error %v", err)
			return err
		}
	}

	if args.Netns == "" {
		log.Println("args.Netns == \"\" sfc-ptp plugin ran successfully")
		return nil
	}

	// There is a netns so try to clean up. Delete can be called multiple times
	// so don't return an error if the device is already removed
	err = ns.WithNetNSPath(args.Netns, func(_ ns.NetNS) error {
		var err error
		_, err = ip.DelLinkByNameAddr(args.IfName)
		if err != nil && err == ip.ErrLinkNotFound {
			return nil
		}
		return err
	})

	if err != nil {
		log.Printf("ns.WithNetNSPath returned error %v", err)
		return err
	}

	log.Println("sfc-ptp plugin ran successfully")
	return nil
}

func main() {
	skel.PluginMain(cmdAdd, cmdCheck, cmdDel, version.All, bv.BuildString("sfc-ptp"))
}

func cmdCheck(args *skel.CmdArgs) error {
	// TODO: implement
	return fmt.Errorf("not implemented")
}
