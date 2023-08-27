package cni

import (
	"fmt"
	"github.com/kubeedge/beehive/pkg/core"
	"github.com/kubeedge/edgemesh/pkg/apis/config/defaults"
	"github.com/kubeedge/edgemesh/pkg/apis/config/v1alpha1"
	"github.com/kubeedge/edgemesh/pkg/clients"
	clientset "k8s.io/client-go/kubernetes"
	"k8s.io/klog/v2"
	"time"
)

// EdgeCni is used for cni traffic control
type EdgeCni struct {
	Config           *v1alpha1.EdgeCniConfig
	kubeClient       clientset.Interface
	ConfigSyncPeriod time.Duration
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
	// TODO:  Add cni.CleanupAndExit()
	err := cni.CleanupAndExit()
	if err != nil {
		klog.ErrorS(err, "Cleanup iptables failed")
	}
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

	// create a meshAdapter
	mesh, err := NewMeshAdapter(c, cli.GetKubeClient())
	if err != nil {
		klog.Errorf("create Mesh adapter err: ", err)
		return nil, err
	}

	return &EdgeCni{
		Config:      c,
		MeshAdapter: mesh,
		kubeClient:  cli.GetKubeClient(),
	}, nil
}
