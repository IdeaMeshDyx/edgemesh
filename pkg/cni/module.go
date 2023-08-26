package cni

import (
	"fmt"
	"github.com/kubeedge/beehive/pkg/core"
	"github.com/kubeedge/edgemesh/pkg/apis/config/defaults"
	"github.com/kubeedge/edgemesh/pkg/apis/config/v1alpha1"
	"github.com/kubeedge/edgemesh/pkg/clients"
	netutil "github.com/kubeedge/edgemesh/pkg/util/net"
	clientset "k8s.io/client-go/kubernetes"
	"k8s.io/klog/v2"
	utiliptables "k8s.io/kubernetes/pkg/util/iptables"
	"k8s.io/utils/exec"
	"net"
	"time"
)

// EdgeCni is used for cni traffic control
type EdgeCni struct {
	EncapIp          net.IP
	Config           *v1alpha1.EdgeCniConfig
	kubeClient       clientset.Interface
	IptInterface     utiliptables.Interface
	execer           exec.Interface
	ConfigSyncPeriod time.Duration
	TunIf            *tunIf
	MeshAdapter      *MeshAdapter
}

// Name of EdgeCni
func (cni *EdgeCni) Name() string {
	return defaults.EdgeCniModuleName
}

// Group of EdgeCni
func (cni *EdgeCni) Group() string {
	return defaults.EdgeCniModuleName
}

// Enable indicates whether enable this module
func (cni *EdgeCni) Enable() bool {
	return cni.Config.Enable
}

// Start EdgeCni
func (cni *EdgeCni) Start() {
	cni.Run()
}

// Shutdown edgeproxy
func (cni *EdgeCni) Shutdown() {
	// err := cni.ProxyServer.CleanupAndExit()
	// TODO:  Add cni.CleanupAndExit()

	//if err != nil {
	//	klog.ErrorS(err, "Cleanup iptables failed")
	//}
}

// Register edgeproxy to beehive modules
func Register(c *v1alpha1.EdgeCniConfig, cli *clients.Clients) error {
	cni, err := newEdgeCni(c, cli)
	if err != nil {
		return fmt.Errorf("register module edgeproxy error: %v", err)
	}
	core.Register(cni)
	return nil
}

func newEdgeCni(c *v1alpha1.EdgeCniConfig, cli *clients.Clients) (*EdgeCni, error) {
	if !c.Enable {
		return &EdgeCni{Config: c}, nil
	}

	// get proxy listen ip
	encapIP, err := netutil.GetInterfaceIP(c.EncapIP)
	if err != nil {
		klog.Errorf("get proxy listen ip err: ", err)
		return nil, err
	}

	// Create a iptables utils.
	execer := exec.New()
	iptIf := utiliptables.New(execer, utiliptables.ProtocolIPv4)

	// create a tun handler
	tun, err := NewTunIf(defaults.TunDeviceName, encapIP)
	if err != nil {
		klog.Errorf("create tun device err: ", err)
		return nil, err
	}

	//

	return &EdgeCni{
		Config:       c,
		EncapIp:      encapIP,
		IptInterface: iptIf,
		TunIf:        tun,
		kubeClient:   cli.GetKubeClient(),
	}, nil
}
