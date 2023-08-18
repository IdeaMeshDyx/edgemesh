package proxy

import (
	"context"
	"fmt"
	"net"
	"os"
	"os/exec"
	"strings"
	"sync"
	"time"

	"github.com/kubeedge/edgemesh/pkg/apis/config/v1alpha1"
	"github.com/kubeedge/edgemesh/pkg/tunnel"
	meshnet "github.com/kubeedge/edgemesh/pkg/util/net"

	"github.com/kubeedge/edgemesh/tests/cni/util"
	apiv1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/informers"
	clientset "k8s.io/client-go/kubernetes"
	"k8s.io/client-go/tools/cache"
	"k8s.io/klog/v2"
)

const (
	LabelKubeedge string = "kubeedge=edgemesh-agent"
	AgentPodName  string = "edgemesh-agent"
	TCP           string = "tcp"
	UDP           string = "udp"
	CNIPort       int    = 40008
)

var tunnelMap []TunnelInfo // 创建的Tunnel list，每个网段对应数个 Tunnel 进程的 port

type Adapter interface {
	// preRun 在 proxy 模块/Tunnel 模块启动前运行，建立数个 Tunnel 隧道专门用于穿透,创建 EDGEMESH 链
	preRun(cfg *v1alpha1.EdgeProxyConfig)

	// Run 主函数
	Run(cfg *v1alpha1.EdgeProxyConfig, stop <-chan struct{})

	// adapterRoute 维护隧道服务,当 P2P 请求增多的时候扩增 Tunnel 数量并选择合适的端口转发
	adapterRoute() error

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
	hostName       string              // 节点名称
	hostCIDR       string              // 本节点的 CIDR地址 【不需要】
	cloud          []string            // 云上的区域网段
	edge           []string            // 边缘的区域网段
	StartChan      chan struct{}       // 用于控制 Tunnel 数量以及多少
	kubeClient     clientset.Interface // 接入 k8s 的客户端，用于同步和获取信息
	namespace      string              // Pod 所处的 Namespace
}

type TunnelInfo struct {
	//  需要链接的容器 IP
	PodIP string
	// 需要连接的节点名称:
	NodeName string
	// 需要连接的节点IP:
	NodeIP string

	// 占用的 Port
	Port int

	// iptables 中是否有 对应规则，1表示有，0表示没有
	status int
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
		namespace:  cfg.Socks5Proxy.Namespace,
	}

	return mesh, nil
}

func (mesh *MeshAdapter) Run(stop <-chan struct{}) error {
	err := mesh.PreRun(stop)
	if err != nil {
		klog.Errorf("PreRun failed: %v", err)
	}
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

	// 获取本节点的 cidr 范围
	mesh.hostCIDR, err = mesh.findLocalCIDR()
	if err != nil {
		klog.Errorf("Error getting loacl CIDR from kubeclient: ", err)
		return err
	}
	// 启动 WatchRoute， 当其他网段 Pod 建立时候，触发adapterRoute
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

func (mesh *MeshAdapter) adapterRoute() error {
	// 获取随机的 Port 端口
	port, err := util.GetPort(50000, 100)
	if err != nil {
		klog.Errorf("Error allocating port:", err)
	}

	// 创建新的 TCP Listner,监听在本节点的随机地址
	addr := &net.TCPAddr{
		IP:   mesh.listenIP,
		Port: port,
	}
	srv, err := net.ListenTCP(TCP, addr)
	if err != nil {
		klog.Errorf("get TCP listener failed:", err)
	}
	klog.Infof("open a tcp proxy,listen addr:[%s]", addr)

	// 插入规则拦截流量
	target := tunnelMap[len(tunnelMap)-1]
	// 插入一条规则将所有到目标 PodIP 的所有流量拦截到EDGEMESH链匹配规则
	ruleEdge := util.Rule{Table: "nat", Chain: "PREROUTING", Spec: []string{"-p", "tcp", "-d", target.PodIP, "-j", "EDGEMESH"}}
	err = mesh.iptables.InsertUnique(ruleEdge, 1)
	if err != nil {
		klog.Errorf("Error inserting rule to PREROUTING chain:", err)
	}

	// 插入规则，在 EDGEMESH 链将目标地址是edge网段的数据包都拦截转发到应用层的进程
	ruleSpec := util.Rule{Table: "nat", Chain: "EDGEMESH", Spec: []string{"-p", "tcp", "-d", target.PodIP, "-j", "DNAT", "--to-destination", addr.String()}}
	err = mesh.iptables.Append(ruleSpec)
	if err != nil {
		klog.Errorf("Error inserting rule: ", err)
	}
	klog.Infof("EdgeMesh chain created and rule inserted successfully.")

	for {
		conn, err := srv.Accept()
		if err != nil {
			klog.Infof("TCP listener failed:", err)
			continue
		}

		go mesh.handleConn(conn)
		klog.Infof("open a meshAdapter proxy,listen addr:[%s],remote node:[%s]", addr, target.NodeName)
	}
}

func (mesh *MeshAdapter) handleConn(conn net.Conn) {
	defer conn.Close()
	// 获取对端Pod容器的 IP 地址
	// 因为是启动在 EdgeMesh 当中的 TCP 占用40008端口
	targetIP, err := mesh.getTargetIpByNodeName(AgentPodName)
	if err != nil {
		klog.Errorf("Unable to get destination IP, %v", err)
		return
	}
	klog.Info("Successfully get destination IP. NodeIP: ", targetIP, ", Port: ", CNIPort)

	// 创建新的 proxyOpt 对象
	proxyOpts := tunnel.ProxyOptions{
		Protocol: TCP,
		NodeName: AgentPodName, // 对段节点的 NodeName
		IP:       targetIP,     // 对端 pod 的IP（由于是 host）
		Port:     int32(CNIPort),
	}
	stream, err := tunnel.Agent.GetProxyStream(proxyOpts)
	if err != nil {
		klog.Errorf("l4 proxy get proxy stream from %s error: %w", proxyOpts.NodeName, err)
		return
	}

	klog.Infof("l4 proxy start proxy data between tcpserver %v", proxyOpts.NodeName)

	meshnet.ProxyConn(stream, conn)

	klog.Infof("Success proxy to %v", conn)

}

func (mesh *MeshAdapter) watchRoute(stop <-chan struct{}) {
	// 监控其他节点创建 Pod 事件，当所创建的 Pod 与节点的 cidr 不相同时候出发 adapterRoute
	// 创建一个Pod资源的事件处理器
	podEventHandler := cache.ResourceEventHandlerFuncs{
		AddFunc: func(obj interface{}) {
			pod := obj.(*apiv1.Pod)
			if pod.Status.Phase == apiv1.PodRunning {
				//  判断是否是跨域 Pod 生成
				crossNet, err := mesh.judgeNet(pod.Status.PodIP)
				if err != nil {
					klog.Errorf("judge Pod IP failed:", err)
				}
				if crossNet {
					// 全局 Tunnel list 当中记录新创建的  Pod 以及对应IP
					// TODO: 去重覆盖，负载均衡等优化
					tunnelMap = append(tunnelMap, TunnelInfo{
						NodeName: pod.Name,
						PodIP:    pod.Status.PodIP,
						status:   0,
					})
					<-mesh.StartChan
					klog.Infof("New pod created: %s, IP: %s\n", pod.Name, pod.Status.PodIP)
				}
			}
		},
	}
	// 设置事件监听器
	factory := informers.NewSharedInformerFactory(mesh.kubeClient, 30*time.Second)
	podInformer := factory.Core().V1().Pods().Informer()
	podInformer.AddEventHandler(podEventHandler)
	// 启动事件监听器
	go podInformer.Run(stop)

	// 创建新的 TCP Listner,监听在本节点的40008 端口
	addr := &net.TCPAddr{
		IP:   mesh.listenIP,
		Port: CNIPort,
	}
	srv, err := net.ListenTCP(TCP, addr)
	if err != nil {
		klog.Errorf("get TCP listener failed:", err)
	}
	klog.Infof("open a tcp proxy,listen addr:[%s]", addr)

	for {
		conn, err := srv.Accept()
		if err != nil {
			klog.Infof("TCP listener failed:", err)
			continue
		}

		go mesh.handleRecieve(conn)
	}
}

func (mesh *MeshAdapter) handleRecieve(conn net.Conn) {
	defer conn.Close()

	// 接收 TCP 流量之后，使用 TUN 将数据包传输到容器网桥
	// 使用 OpenTun 函数创建 TUN 设备
	tun, ifname, err := util.OpenTun("tun0")
	if err != nil {
		klog.Errorf("create TUN device  failed: %v", err)
	}
	klog.Infof("TUN interface created: %s\n", ifname)
	defer tun.Close()

	// 配置 TUN 设备
	// 这个实验阶段，后期一步步修改
	tunIP := "10.244.0.1"
	tunNetmask := "255.255.0.0"
	cmd := exec.Command("ifconfig", ifname, tunIP, "netmask", tunNetmask, "up")
	if err := cmd.Run(); err != nil {
		klog.Errorf("Error configuring TUN device: %v\n", err)
	}

	// 添加路由规则以将 TUN 设备接收到的 IP 数据包转发到本节点的 Pod IP 网段
	podCIDR := "10.244.0.0/16"
	cmd = exec.Command("route", "add", "-net", podCIDR, "dev", ifname)
	if err := cmd.Run(); err != nil {
		klog.Errorf("Error adding route: %v\n", err)
	}

	// 在一个循环中，从 TCP 服务器读取数据包，并将它们写入 TUN 设备
	buf := make([]byte, 4096)
	// 从 TCP 服务器读取数据包
	n, err := conn.Read(buf)
	if err != nil {
		klog.Errorf("Error reading from connection: %v\n", err)
	}

	// 将接收到的数据包写入 TUN 设备
	_, err = tun.Write(buf[:n])
	if err != nil {
		klog.Errorf("Error writing to TUN device: %v\n", err)
	}

}

func (mesh *MeshAdapter) judgeNet(podIP string) (bool, error) {
	// 解析 IP 地址
	ip := net.ParseIP(podIP)
	// 解析 CIDR
	_, cidr, _ := net.ParseCIDR(mesh.hostCIDR)
	// 检查 IP 是否在 CIDR 范围内
	return cidr.Contains(ip), nil
}

// getTargetIpByNodeName Returns the real IP address of the node
// We must obtain the real IP address of the node to communicate, so we need to query the IP address of the edgemesh-agent on the node
// Because users may modify the IP addresses of edgemesh-0 and edgecore. If used directly, it may cause errors
func (mesh *MeshAdapter) getTargetIpByNodeName(nodeName string) (targetIP string, err error) {
	pods, err := mesh.kubeClient.CoreV1().Pods(mesh.namespace).List(context.Background(), metav1.ListOptions{FieldSelector: "spec.nodeName=" + nodeName, LabelSelector: LabelKubeedge})
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
