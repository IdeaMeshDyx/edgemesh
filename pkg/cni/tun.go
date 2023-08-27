package cni

import (
	"fmt"
	"net"
	"os/exec"
	"syscall"

	buf "github.com/liuyehcf/common-gtools/buffer"
	"github.com/songgao/water"
	"k8s.io/klog/v2"
)

const (
	tunDevice   = "/dev/net/tun"
	ifnameSize  = 16
	ReceiveSize = 50
	SendSize    = 50
)

type tunIf struct {
	// Name of Tun
	tunName string

	// IP Tun device listen at
	tunIp net.IP

	// Tun interface to handle the tun device
	tunDev *water.Interface

	// Receive pipeline for transport data to p2p
	ReceivePipe chan []byte

	// Tcp pipeline for transport data to p2p
	WritePipe chan []byte

	// filedescribtion
	fd int
}

// NewTunIf New Tuninterface to handle Tun dev
func NewTunIf(name string, Ip net.IP) (*tunIf, error) {
	tun, err := water.New(water.Config{
		DeviceType: water.TUN,
	})
	if err != nil {
		klog.Errorf("create TunInterface failed:", err)
		return nil, err
	}

	// create raw socket for communication
	fd, err := syscall.Socket(syscall.AF_INET, syscall.SOCK_RAW, syscall.IPPROTO_RAW)
	if err != nil {
		klog.Errorf("failed to create raw socket", err)
		return nil, err
	}

	klog.Infof("Tun Interface Name: %s\n", name)
	return &tunIf{
		tunIp:       Ip,
		tunDev:      tun,
		tunName:     name,
		fd:          fd,
		ReceivePipe: make(chan []byte, ReceiveSize),
		WritePipe:   make(chan []byte, SendSize),
	}, nil
}

// SetupTunDevice  with IP
func (tun *tunIf) SetupTunDevice() error {
	err := ExecCommand(fmt.Sprintf("ip address add %s dev %s", tun.tunIp.String(), tun.tunDev.Name()))
	if err != nil {
		return err
	}
	klog.Info("add %s dev %s succeed ", tun.tunIp.String(), tun.tunName)

	err = ExecCommand(fmt.Sprintf("ip link set dev %s up", tun.tunName))
	if err != nil {
		return err
	}
	klog.Info("set dev %s up succeed", tun.tunName)
	return nil
}

// AddRouteToTun route actions for those CIDR
func (tun *tunIf) AddRouteToTun(cidr string) error {
	err := ExecCommand(fmt.Sprintf("ip route add table main %s dev %s", cidr, tun.tunName))
	if err != nil {
		return err
	}
	klog.Info("ip route add table main %s dev %s succeed", cidr, tun.tunName)
	return nil
}

func ExecCommand(command string) error {
	//TODO： change this cmd to code
	klog.Infof("exec command '%s'\n", command)

	cmd := exec.Command("/bin/bash", "-c", command)

	err := cmd.Run()
	if err != nil {
		klog.Errorf("failed to execute Command %s , err:", command, err)
		return err
	}
	// check is dev setup right
	if state := cmd.ProcessState; state.Success() {
		klog.Errorf("exec command '%s' failed, code=%d", command, state.ExitCode(), err)
		return err
	}
	return nil
}

// TunReceiveLoop  receive data from inside Pods
func (tun *tunIf) TunReceiveLoop() {
	// buffer to receive data
	buffer := buf.NewRecycleByteBuffer(65536)
	packet := make([]byte, 65536)
	// TODO: improve the following double for logic
	for {
		// read from tun Dev
		n, err := tun.tunDev.Read(packet)
		if err != nil {
			klog.Error("failed to read data from tun", err)
			break
		}

		// get data from tun
		buffer.Write(packet[:n])
		for {
			// Get IP frame to byte data to encapsulate
			frame, err := ParseIPFrame(buffer)

			if err != nil {
				klog.Errorf("Parse frame failed:", err)
				buffer.Clean()
				break
			}
			if frame == nil {
				break
			}

			// transfer data to libP2P
			tun.ReceivePipe <- frame.ToBytes()
			// print out the reception data
			klog.Infof("receive from tun, send through tunnel , source %s target %s len %d", frame.GetSourceIP(), frame.GetTargetIP(), frame.GetPayloadLen())
		}
	}
	return
}

// TunWriteLoop  send data back to the pod
func (tun *tunIf) TunWriteLoop() {
	// buffer to write data
	buffer := buf.NewRecycleByteBuffer(65536)
	packet := make([]byte, 65536)
	for {
		// transfer data to libP2P
		//tun.TcpRecievePipe <- frame.ToBytes()
		packet = <-tun.WritePipe
		if n := len(packet); n == 0 {
			klog.Error("failed to read from tcp tunnel")
		}
		buffer.Write(packet[:len(packet)])

		for {
			// get IP data inside
			frame, err := ParseIPFrame(buffer)
			if err != nil {
				klog.Errorf("failed to parse ip package from tcp tunnel", err)
			}

			if err != nil {
				klog.Errorf("Parse frame failed:", err)
				buffer.Clean()
				break
			}
			if frame == nil {
				break
			}

			klog.Infof("receive from tunnel, send through raw socket, source %s target %s len %d", frame.GetSourceIP(), frame.GetTargetIP(), frame.GetPayloadLen())

			// send ip frame through raw socket
			addr := syscall.SockaddrInet4{
				Addr: IPToArray4(frame.Target),
			}
			// directly send to that IP
			err = syscall.Sendto(tun.fd, frame.ToBytes(), 0, &addr)
			if err != nil {
				klog.Errorf("failed to send data through raw socket", err)
			}
		}
	}
}

// CleanTunDevice delete all the Route and change iin kernel
func (tun *tunIf) CleanTunDevice() error {
	err := ExecCommand(fmt.Sprintf("ip link del dev %s mode tun", tun.tunName))
	if err != nil {
		klog.Errorf("Delete Tun Device  failed", err)
		return err
	}
	klog.Infof("Set dev %s down\n", tun.tunName)
	return nil
}

// CleanTunRoute Delete All Routes attach to Tun
func (tun *tunIf) CleanTunRoute() error {
	err := ExecCommand(fmt.Sprintf("ip route flush %s", tun.tunIp))
	if err != nil {
		klog.Errorf("Delete Tun Route  failed", err)
		return err
	}
	fmt.Printf("Removed route from dev %s\n", tun.tunName)
	return nil
}

// CleanSingleTunRoute Delete Single Route attach to Tun
func (tun *tunIf) CleanSingleTunRoute(cidr string) error {
	err := ExecCommand(fmt.Sprintf("ip route del table main %s dev %s", cidr, tun.tunName))
	if err != nil {
		klog.Errorf("Delete Tun Route  failed", err)
		return err
	}
	klog.Infof("Removed route for %s from dev %s\n", cidr, tun.tunName)
	return nil
}
