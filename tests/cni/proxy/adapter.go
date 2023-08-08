package proxy

import (
	"context"
	"fmt"
	"log"
	"net"
	"os"
	"strings"
	"sync"
	"time"

	apiv1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/informers"
	clientset "k8s.io/client-go/kubernetes"
	"k8s.io/client-go/tools/cache"
	"k8s.io/klog/v2"

	"github.com/kubeedge/edgemesh/pkg/apis/config/v1alpha1"
	"github.com/kubeedge/edgemesh/pkg/tunnel"
	"github.com/kubeedge/edgemesh/tests/cni/util"
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

const (
	LabelKubeedge string = "kubeedge=edgemesh-agent"
	AgentPodName  string = "edgemesh-agent"
	TCP           string = "tcp"
	UDP           string = "udp"
	CNIPort       string = "40008"
)

var tunnelMap map[string]string // 创建的Tunnel list，每个网段对应数个 Tunnel 进程的 port

type Adapter interface {
	// preRun 在 proxy 模块/Tunnel 模块启动前运行，建立数个 Tunnel 隧道专门用于穿透,创建 EDGEMESH 链
	preRun(cfg *v1alpha1.EdgeProxyConfig)

	// Run
	Run(cfg *v1alpha1.EdgeProxyConfig, stop <-chan struct{})

	// adapterRoute 维护隧道服务,当 P2P 请求增多的时候扩增 Tunnel 数量并选择合适的端口转发
	adapterRoute() error

	// 获取 EdgeTunnel 的端口并写入全局变量 tunnelMap
	// @TODO 创建独立的 EDGETUNNEL
	getTunnel() error

	// 依据 Tunnel 信息插入转发规则
	applyRules() error

	// 一直运行
	watchRoute(stop <-chan struct{}) error

	// 删除所有的Adapter创建的规则和链
	cleanUp() error
}

type MeshAdapter struct {
	syncPeriod     time.Duration
	minSyncPeriod  time.Duration
	udpIdleTimeout time.Duration
	iptables       *util.Iptutil       // iptables util ， 用于调用 iptables 相关行为
	tunnelMapMutex sync.Mutex          // protects Tunnel Map
	listenIP       net.IP              // edgemesh 运行的地址【不需要】
	hostIP         net.IP              // 节点的地址【不需要】
	hostCIDR       string              // 本节点的 CIDR地址 【不需要】
	cloud          []string            // 云上的区域网段
	edge           []string            // 边缘的区域网段
	proxyPorts     util.PortAllocator  // 分配 Port TODO : 修改逻辑，使 Port 分配符合 Tunnel 的逻辑 【不需要】
	StartChan      chan struct{}       // 用于控制 Tunnel 数量以及多少
	kubeClient     clientset.Interface // 接入 k8s 的客户端，用于同步和获取信息
}

type AdapterProxyOpt struct {
	//IP:PORT,用于本地监听的地址和端口
	LocalAddr string
	// 需要连接的节点名称:
	NodeName string
	//远程的端口：
	RemotePort int32
}

// 初始化
func New(cfg *v1alpha1.EdgeProxyConfig, ip net.IP, kubeClient clientset.Interface) (*MeshAdapter, error) {
	// 初始化iptables
	iptables, err := util.New()
	if err != nil {
		fmt.Println("Error initializing iptables: ", err)
		return nil, err
	}

	// 读取 cfg 文件获取集群的网段情况
	// TODO： 这个是一次性的信息，怎样应对后期集群网段变化的情况
	cloud, edge, err := getCIDR(cfg.MeshCIDR)
	if err != nil {
		klog.Errorf("get CIDR from config failed: %v", err)
		return nil, err
	}

	mesh := &MeshAdapter{
		iptables:   iptables,
		listenIP:   ip,
		cloud:      cloud,
		edge:       edge,
		kubeClient: kubeClient,
	}

	return mesh, nil
}

// 从配置文件中获取不同网段的地址
func (mesh *MeshAdapter) Run(stop <-chan struct{}) error {
	go mesh.PreRun(stop)
	for {
		select {
		case _, ok := <-stop:
			if !ok {
				klog.ErrorS(nil, "Stop channel has been closed")
			}
			return nil
		case _, ok := <-mesh.StartChan:
			if !ok {
				klog.ErrorS(nil, "Start channel has been closed")
			} else {
				go mesh.adapterRoute()
			}
		}
	}
}

func (mesh *MeshAdapter) PreRun(stop <-chan struct{}) error {
	// 在 nat table 创建EdgeMesh链
	err := mesh.iptables.NewChain("nat", "EDGEMESH")
	if err != nil {
		klog.Errorf("Error creating EdgeMesh chains: ", err)
		return err
	}

	// 遍历不同的 CIDR，为每个跨网段的 CIDR 添加转发规则且启动Tunnel
	// 目前跨网段的标准是： 与本地节点IP不在一个网段
	mesh.hostCIDR, err = mesh.findLocalCIDR()
	if err != nil {
		klog.Errorf("Error getting loacl CIDR from kubeclient: ", err)
		return err
	}
	// 启动 WatchRoute ，用于负载均衡的算法，1. 初次有四色 map 发生
	go mesh.watchRoute(stop)

	return nil

}

func (mesh *MeshAdapter) findLocalCIDR() (string, error) {
	// 获取目前节点的名称
	nodeName := os.Getenv("NODE_NAME")
	if nodeName == "" {
		panic("NODE_NAME environment variable not set")
	}
	// 使用 clientset 获取节点信息
	node, err := mesh.kubeClient.CoreV1().Nodes().Get(context.Background(), nodeName, metav1.GetOptions{})
	if err != nil {
		panic(err.Error())
	}
	// 从节点信息中提取 Pod CIDR
	podCIDR := node.Spec.PodCIDR
	return podCIDR, nil
}

// getCIDR 解析 config 文件获取集群网段分配情况
func getCIDR(cfg *v1alpha1.MeshCIDR) ([]string, []string, error) {
	cloud := cfg.CloudCIDR
	edge := cfg.EdgeCIDR

	if err := validateCIDRs(cloud); err != nil {
		klog.ErrorS(err, "Cloud CIDR is not valid", "cidr", cloud)
		return cloud, edge, err
	}

	if err := validateCIDRs(edge); err != nil {
		klog.ErrorS(err, "Edge CIDR is not valid", "cidr", edge)
		return cloud, edge, err
	}

	klog.Infof("dyx: Parsed CIDR of Cloud: %v \n   Edge: %v \n", cloud, edge)
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

func (mesh *MeshAdapter) adapterRoute() error {
	// 创建新的 UDP Listner
	srv, err := net.Listen(`tcp`, opt.LocalAddr)
	if err != nil {
		log.Panicln(err)
	}
	for {
		conn, err := srv.Accept()
		if err != nil {
			log.Println(err)
			continue
		}

		zaplog.SugarLogger.Infof("open a rdp proxy,listen addr:[%s],remote node:[%s]", opt.LocalAddr, opt.NodeName)

		go r.handleConn(opt, conn)
	}
}

func (mesh *MeshAdapter) getTunnel(cidr string) error {

	// 依据输入的 CIDR 获取随机的端口

	// 使用该端口结合 listenIP 启动Tunnel

	// 为这个 Tunnel 插入 iptables 规则
	mesh.applyRules()

	return nil
}

func (mesh *MeshAdapter) applyRules() error {
	return nil
}

func (mesh *MeshAdapter) watchRoute(stop <-chan struct{}) {
	// 1. 第一类触发 Adapter 运行，当本节点创建了新的Pod
	// 创建一个Pod资源的事件处理器
	podEventHandler := cache.ResourceEventHandlerFuncs{
		AddFunc: func(obj interface{}) {
			pod := obj.(*apiv1.Pod)
			if pod.Status.Phase == apiv1.PodRunning {
				// 全局 Tunnel list 当中记录新创建的  Pod 以及IP
				tunnelMap[pod.Name] = pod.Status.PodIP
				<-mesh.StartChan
				klog.Infof("New pod created: %s, IP: %s\n", pod.Name, pod.Status.PodIP)
			}
		},
	}
	// 设置事件监听器
	factory := informers.NewSharedInformerFactory(mesh.kubeClient, 30*time.Second)
	podInformer := factory.Core().V1().Pods().Informer()
	podInformer.AddEventHandler(podEventHandler)

	// 启动事件监听器
	go podInformer.Run(stop)
}

// getTargetIpByNodeName Returns the real IP address of the node
// We must obtain the real IP address of the node to communicate, so we need to query the IP address of the edgemesh-agent on the node
// Because users may modify the IP addresses of edgemesh-0 and edgecore. If used directly, it may cause errors
func (mesh *MeshAdapter) getTargetIpByNodeName(nodeName string) (targetIP string, err error) {
	pods, err := mesh.kubeClient.CoreV1().Pods(mesh.config.Namespace).List(context.Background(), metav1.ListOptions{FieldSelector: "spec.nodeName=" + nodeName, LabelSelector: LabelKubeedge})
	if err != nil {
		return "", err
	}
	ip, err := "", fmt.Errorf("edgemesh agent not found on node [%s]", nodeName)
	for _, pod := range pods.Items {
		if strings.Contains(pod.Name, AgentPodName) {
			ip = pod.Status.PodIP
			err = nil
		}
	}

	return ip, err
}

func (mesh *MeshAdapter) handleConn(rdpOpt TunnelProxyOpt, conn net.Conn) {
	defer conn.Close()

	//	解析目标 Pod 地址对应的节点地址

	proxyOpts := tunnel.ProxyOptions{
		Protocol: UDP,
		NodeName: rdpOpt.NodeName,
		IP:       "127.0.0.1",
		Port:     rdpOpt.RemoteRdpPort,
	}
	stream, err := tunnel.Agent.GetProxyStream(proxyOpts)
	if err != nil {
		klog.Errorf("l4 proxy get proxy stream from %s error: %w", proxyOpts.NodeName, err)
		return
	}

	klog.Infof("l4 proxy start proxy data between tcpserver %v", proxyOpts.NodeName)

	util.ProxyConn(stream, conn)

	klog.Infof("Success proxy to %v", conn)

}

func (mesh *MeshAdapter) handleSubnetEvents(batch []lease.Event) {
	for _, evt := range batch {
		switch evt.Type {
		case lease.EventAdded:
			if evt.Lease.Attrs.BackendType != n.BackendType {
				log.Warningf("Ignoring non-%v subnet: type=%v", n.BackendType, evt.Lease.Attrs.BackendType)
				continue
			}

			if evt.Lease.EnableIPv4 {
				log.Infof("Subnet added: %v via %v", evt.Lease.Subnet, evt.Lease.Attrs.PublicIP)

				route := n.GetRoute(&evt.Lease)
				routeAdd(route, netlink.FAMILY_V4, n.addToRouteList, n.removeFromV4RouteList)
			}

			if evt.Lease.EnableIPv6 {
				log.Infof("Subnet added: %v via %v", evt.Lease.IPv6Subnet, evt.Lease.Attrs.PublicIPv6)

				route := n.GetV6Route(&evt.Lease)
				routeAdd(route, netlink.FAMILY_V6, n.addToV6RouteList, n.removeFromV6RouteList)
			}

		case lease.EventRemoved:
			if evt.Lease.Attrs.BackendType != n.BackendType {
				log.Warningf("Ignoring non-%v subnet: type=%v", n.BackendType, evt.Lease.Attrs.BackendType)
				continue
			}

			if evt.Lease.EnableIPv4 {
				log.Info("Subnet removed: ", evt.Lease.Subnet)

				route := n.GetRoute(&evt.Lease)
				// Always remove the route from the route list.
				n.removeFromV4RouteList(*route)

				if err := netlink.RouteDel(route); err != nil {
					log.Errorf("Error deleting route to %v: %v", evt.Lease.Subnet, err)
				}
			}

			if evt.Lease.EnableIPv6 {
				log.Info("Subnet removed: ", evt.Lease.IPv6Subnet)

				route := n.GetV6Route(&evt.Lease)
				// Always remove the route from the route list.
				n.removeFromV6RouteList(*route)

				if err := netlink.RouteDel(route); err != nil {
					log.Errorf("Error deleting route to %v: %v", evt.Lease.IPv6Subnet, err)
				}
			}

		default:
			log.Error("Internal error: unknown event type: ", int(evt.Type))
		}
	}
}
