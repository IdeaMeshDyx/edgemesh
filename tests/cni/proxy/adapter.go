package adapter

import (
	"fmt"

	"ideammesh/adapter/iptables"

	"github.com/spf13/viper"

	iptables "github.com/kubeedge/edgemesh/pkg/test/iptables"
)

func main() {
	// 初始化iptables
	ipt, err := iptables.New()
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

type Adapter interface {
	// preRun 在 proxy 模块/Tunnel 模块启动前运行，建立数个 Tunnel 隧道专门用于穿透
	preRun() error

	// 配置文件中获取云边的网段地址
	getCIDR() error

	// 获取 EdgeTunnel 的端口
	// @TODO 创建独立的 EDGETUNNEL
	getTunnel() error

	// 创建 EDGEMESH 链 并依据Tunnel 信息插入转发规则
	applyRules() (bool, error)

	// 监视表中的规则，如果 Tunnel 或者 Config 文件发生修改，立即修改
	watchRules() error

	// 修改（增加/删除）表中拦截到 Tunnel 的规则
	updateRules() error
}

type MeshAdapter struct {
	// 创建的Tunnel list，每个 Pod IP地址对应一个端口
	tunnel map[int]string
	// 云上的区域网段
	cloud []string
	// 边缘的区域网段
	edge []string
}

// 从配置文件中获取不同网段的地址
func (mesh *MeshAdapter) getCIDR() error {
	// 读取配置文件
	// TODO： 接入到 EdgeMesh 中，需要商量这个配置文件的位置
	viper.SetConfigName("config")
	viper.SetConfigType("yaml")
	viper.AddConfigPath("./config")
	err := viper.ReadInConfig()
	if err != nil {
		fmt.Println("Error reading config file: ", err)
		return err
	}

	edgeIP := viper.GetStringSlice("edge.ip")
	cloudIP := viper.GetStringSlice("cloud.ip")

	// TODO: 去重还有标记
	mesh.edge = append(mesh.edge, edgeIP...)
	mesh.cloud = append(mesh.cloud, cloudIP...)

	fmt.Printf("get ip info: edge %s, cloud info: %s ", edgeIP, cloudIP)
	return nil
}

func (mesh *MeshAdapter) getTunnel() error { return nil }

func (mesh *MeshAdapter) applyRules() (bool, error) { return true, nil }
func (mesh *MeshAdapter) watchRules() error         { return nil }
func (mesh *MeshAdapter) updateRules() error        { return nil }
