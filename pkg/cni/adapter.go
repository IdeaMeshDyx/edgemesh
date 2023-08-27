package cni

import (
	"context"
	"fmt"
	"io"
	"net"
	"os"
	"time"

	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	clientset "k8s.io/client-go/kubernetes"
	"k8s.io/klog/v2"
	utiliptables "k8s.io/kubernetes/pkg/util/iptables"
	"k8s.io/utils/exec"

	"github.com/kubeedge/edgemesh/pkg/apis/config/defaults"
	"github.com/kubeedge/edgemesh/pkg/apis/config/v1alpha1"
	"github.com/kubeedge/edgemesh/pkg/tunnel"
	utilnet "github.com/kubeedge/edgemesh/pkg/util/net"
)

type Adapter interface {
	// HandleReceive deal with data from Pod to Tunnel
	HandleReceive()

	// HandleSend deal with data form Tunnel to Pod
	HandleSend()

	// WatchRoute watch CIDR in overlayNetwork and insert Route to Tun dev
	WatchRoute() error

	// CloseRoute close all the Tun and stream
	CloseRoute()
}

var _ Adapter = (*MeshAdapter)(nil)

type MeshAdapter struct {
	kubeClient       clientset.Interface
	IptInterface     utiliptables.Interface
	execer           exec.Interface
	ConfigSyncPeriod time.Duration
	TunIf            *tunIf
	EncapsulationIP  net.IP
	HostCIDR         string
	CloudCIDRs       []string
	EdgeCIDRs        []string
	PodTunnel        net.Conn
}

func NewMeshAdapter(cfg *v1alpha1.EdgeCniConfig, cli clientset.Interface) (*MeshAdapter, error) {
	// get pod network info from cfg and APIServer
	// TODO： just one time work ,so later need to upgrade this
	cloud, edge, err := getCIDR(cfg.MeshCIDRConfig)
	if err != nil {
		klog.Errorf("get CIDR from config failed: %v", err)
		return nil, err
	}
	local, err := findLocalCIDR(cli)
	if err != nil {
		klog.Errorf("get localCIDR from apiserver failed: %v", err)
		return nil, err
	}

	// get proxy listen ip
	encapIP := net.ParseIP(cfg.EncapsulationIP)

	// Create a iptables utils.
	execer := exec.New()
	iptIf := utiliptables.New(execer, utiliptables.ProtocolIPv4)

	// create a tun handler
	tun, err := NewTunIf(defaults.TunDeviceName, encapIP)
	if err != nil {
		klog.Errorf("create tun device err: ", err)
		return nil, err
	}
	err = tun.SetupTunDevice()
	if err != nil {
		klog.Errorf("tun dev setup err: ", err)
		return nil, err
	}

	return &MeshAdapter{
		kubeClient:      cli,
		IptInterface:    iptIf,
		TunIf:           tun,
		EncapsulationIP: encapIP,
		HostCIDR:        local,
		EdgeCIDRs:       edge,
		CloudCIDRs:      cloud,
	}, nil
}

func (mesh *MeshAdapter) Run() {
	// start Tun Recieve and get data
	go mesh.TunIf.TunReceiveLoop()

	// start Tun Write and send data
	go mesh.TunIf.TunWriteLoop()

	// get data from receive pipeline
	go mesh.HandleReceive()

	// send data from Write pipeline
	go mesh.HandleSend()
}

func (mesh *MeshAdapter) HandleReceive() {
	// 创建新的 proxyOpt 对象
	cniOpts := tunnel.CNIAdapterOptions{
		Protocol: TCP,
		NodeName: AgentPodName, // 对段节点的 NodeName
	}
	for {
		packet := <-mesh.TunIf.ReceivePipe
		_, err := mesh.PodTunnel.Write(packet)
		if err != nil {
			klog.Errorf("Error writing data: %v\n", err)
			return
		}
		stream, err := tunnel.Agent.GetCNIAdapterStream(cniOpts)
		if err != nil {
			klog.Errorf("l3 adapter get proxy stream from %s error: %w", cniOpts.NodeName, err)
			return
		}
		klog.Infof("l3 adapter start proxy data between nodes %v", cniOpts.NodeName)

		utilnet.ProxyConn(stream, mesh.PodTunnel)

		klog.Infof("Success proxy to %v", mesh.PodTunnel)
	}
}

func (mesh *MeshAdapter) HandleSend() {
	buf := make([]byte, 1024)

	for {
		n, err := mesh.PodTunnel.Read(buf)
		if err != nil {
			if err != io.EOF {
				klog.Errorf("Error reading data: %v\n", err)
			}
			break
		}
		mesh.TunIf.WritePipe <- buf[:n]
	}

}

func (mesh *MeshAdapter) CloseRoute() {}

func (mesh *MeshAdapter) WatchRoute() error {
	// insert basic route to Tundev
	allCIDR := append(mesh.EdgeCIDRs, mesh.CloudCIDRs...)
	for _, cidr := range allCIDR {
		crossNet, err := mesh.CheckTunCIDR(cidr)
		if err != nil {
			klog.Errorf("Check if PodCIDR cross the  subnet failed:", err)
			return err
		}
		if crossNet {
			err = mesh.TunIf.AddRouteToTun(cidr)
			if err != nil {
				klog.Errorf("Add route to TunDev failed:", err)
				return err
			}
		}
	}
	return nil
	// TODO： wacth the subNetwork event and if the cidr changes ,apply that change to node
}

// EncapsulateData add proxyOPt head to Byte frame
func (mesh *MeshAdapter) EncapsulateData() {}

// DecapsulateData get origin byte frame
func (mesh *MeshAdapter) DecapsulateData() {}

// getCIDR read from config file and get edge/cloud cidr user set
func getCIDR(cfg *v1alpha1.MeshCIDRConfig) ([]string, []string, error) {
	cloud := cfg.CloudCIDR
	edge := cfg.EdgeCIDR

	if err := validateCIDRs(cloud); err != nil {
		klog.ErrorS(err, "Cloud CIDR is not valid", "cidr", cloud)
		return nil, nil, err
	}

	if err := validateCIDRs(edge); err != nil {
		klog.ErrorS(err, "Edge CIDR is not valid", "cidr", edge)
		return nil, nil, err
	}

	klog.Infof("Parsed CIDR of Cloud: %v \n   Edge: %v \n", cloud, edge)
	return cloud, edge, nil
}

// check if the address validate
func validateCIDRs(cidrs []string) error {
	for _, cidr := range cidrs {
		if _, _, err := net.ParseCIDR(cidr); err != nil {
			return fmt.Errorf("invalid CIDR %s: %w", cidr, err)
		}
	}
	return nil
}

// get Local Pod CIDR
func findLocalCIDR(cli clientset.Interface) (string, error) {
	nodeName := os.Getenv("NODE_NAME")
	if nodeName == "" {
		klog.Errorf("NODE_NAME environment variable not set")
		return "", fmt.Errorf("the env NODE_NAME is not set")
	}

	// use clientset to get local info
	node, err := cli.CoreV1().Nodes().Get(context.Background(), nodeName, metav1.GetOptions{})
	if err != nil {
		klog.Errorf("get Node info from Apiserver failed:", err)
		return "", fmt.Errorf("failed to get Node: %w", err)
	}
	podCIDR := node.Spec.PodCIDR
	return podCIDR, nil
}

// CheckTunCIDR  if the cidr is not  in the same network
func (mesh *MeshAdapter) CheckTunCIDR(outerCidr string) (bool, error) {
	outerIP, outerNet, err := net.ParseCIDR(outerCidr)
	if err != nil {
		klog.Error("failed to parse outerCIDR: %v", err)
		return false, err
	}
	_, hostNet, err := net.ParseCIDR(mesh.HostCIDR)
	if err != nil {
		klog.Error("failed to parse hostCIDR: %v", err)
		return false, err
	}
	return hostNet.Contains(outerIP) && hostNet.Mask.String() == outerNet.Mask.String(), nil
}
