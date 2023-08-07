package proxy

import (
	"fmt"
	"net"
	"sync"
	"time"

	clientset "k8s.io/client-go/kubernetes"
	"k8s.io/klog/v2"

	"github.com/kubeedge/edgemesh/pkg/apis/config/v1alpha1"
	"github.com/kubeedge/edgemesh/pkg/proxy"
	"github.com/kubeedge/edgemesh/pkg/test/cni/util"
)

/**
func main() {
	// 初始化iptables
	ipt, err := Ipt.New()
	if err != nil {
		fmt.Println("Error initializing iptables: ", err)
		return
	}

	// 在 nat table 创建EdgeMesh链
	err = ipt.NewChain("nat", "EDGEMESH")
	if err != nil {
		fmt.Println("Error creating EdgeMesh chains: ", err)
		return
	}

	// 读取配置文件
	// TODO： 接入到 EdgeMesh 中，需要商量这个配置文件的位置
	viper.SetConfigName("config")
	viper.SetConfigType("yaml")
	viper.AddConfigPath("./config")
	err = viper.ReadInConfig()
	if err != nil {
		fmt.Println("Error reading config file: ", err)
		return
	}

	//edgeIP := viper.GetStringSlice("edge.ip")
	//cloudIP := viper.GetStringSlice("cloud.ip")

	// 插入一条规则将所有到10.244.12.0/24网段的所有协议的流量拦截到EDGEMESH链匹配规则
	ruleEdge := iptables.Rule{"nat", "PREROUTING", []string{"-p", "all", "-d", "10.244.12.0/24", "-j", "EDGEMESH"}}
	err = ipt.InsertUnique(ruleEdge, 1)
	if err != nil {
		fmt.Println("Error inserting rule to PREROUTING chain:", err)
		return
	}

	// 插入规则，在 PREROUTING 时候将目标地址是edge网段的数据包都拦截转发到应用层的进程
	ruleSpec := iptables.Rule{"nat", "EDGEMESH", []string{"-p", "all", "-d", "10.244.12.0/24", "-j", "DNAT", "--to-destination", "169.254.96.16:42707"}}
	err = ipt.Append(ruleSpec)
	if err != nil {
		fmt.Println("Error inserting rule: ", err)
		return
	}
	fmt.Println("EdgeMesh chain created and rule inserted successfully.")
}
**/

type Adapter interface {
	// preRun 在 proxy 模块/Tunnel 模块启动前运行，建立数个 Tunnel 隧道专门用于穿透,创建 EDGEMESH 链
	Start(cfg *v1alpha1.EdgeProxyConfig) error

	// 配置文件中获取云边的网段地址
	getCIDR(cfg *v1alpha1.EdgeProxyConfig) error

	// 获取 EdgeTunnel 的端口
	// @TODO 创建独立的 EDGETUNNEL
	getTunnel() error

	// 依据 Tunnel 信息插入转发规则
	applyRules() (bool, error)

	// 监视表中的规则，如果 Tunnel 或者 Config 文件发生修改，立即修改
	watchRules() error

	// 修改（增加/删除）表中拦截到 Tunnel 的规则
	updateRules() error

	// 删除所有的Adapter创建的规则和链
	cleanUp() error
}

type MeshAdapter struct {
	syncPeriod     time.Duration
	minSyncPeriod  time.Duration
	udpIdleTimeout time.Duration
	iptables       util.Iptutil     // iptables util ， 用于调用 iptables 相关行为
	tunnelMapMutex sync.Mutex       // protects Tunnel Map
	tunnel         map[string][]int // 创建的Tunnel list，每个网段对应数个 Tunnel 进程的 port
	listenIP       net.IP
	hostIP         net.IP
	cloud          []string            // 云上的区域网段
	edge           []string            // 边缘的区域网段
	proxyPorts     util.PortAllocator  // 分配 Port TODO : 修改逻辑，使 Port 分配符合 Tunnel 的逻辑
	stopChan       chan struct{}       // 用于控制 Tunnel 数量以及多少
	Socks5Proxy    *proxy.Socks5Proxy  // 创建 Tunnel 对象
	kubeClient     clientset.Interface // 接入 k8s 的客户端，用于同步和获取信息
}

// 初始化
func New() (*MeshAdapter, error) {
	var client clientset.Interface
	// 初始化iptables
	iptables, err := util.Iptutil.New()
	if err != nil {
		fmt.Println("Error initializing iptables: ", err)
		return nil, err
	}

	mesh := &MeshAdapter{
		iptables:   iptables,
		kubeClient: client,
	}

	return mesh, nil
}

// 从配置文件中获取不同网段的地址
func (mesh *MeshAdapter) Start(cfg *v1alpha1.EdgeProxyConfig) error {
	// 从配置文件当中获取 云边的地址
	mesh.getCIDR(cfg)
	klog.Infof("======dyx=======Success get CIDR from config, cloud is %v, edge is %v============", mesh.cloud, mesh.edge)
	return nil
}

func (mesh *MeshAdapter) getCIDR(cfg *v1alpha1.EdgeProxyConfig) error {

	mesh.cloud = cfg.MeshCIDR.CloudCIDR
	mesh.edge = cfg.MeshCIDR.EdgeCIDR

	return nil
}
func (mesh *MeshAdapter) getTunnel() error          { return nil }
func (mesh *MeshAdapter) applyRules() (bool, error) { return true, nil }
func (mesh *MeshAdapter) watchRules() error         { return nil }
func (mesh *MeshAdapter) updateRules() error        { return nil }
