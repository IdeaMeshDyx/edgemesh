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
	tunDevice  = "/dev/net/tun"
	ifnameSize = 16
)

type tunIf struct {
	// Name of Tun
	tunName string

	// IP Tun device listen at
	tunIp net.IP

	// Tun interface to handle the tun device
	tunDev *water.Interface

	// Tcp pipeline for transport data to p2p
	TcpRecievePipe chan []byte

	// Tcp pipeline for transport data to p2p
	TcpWritePipe chan []byte

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
		tunIp:   Ip,
		tunDev:  tun,
		tunName: name,
		fd:      fd,
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

// TunRecieveLoop  recieve data from inside Pods
func (tun *tunIf) TunRecieveLoop() {
	// buffer to recieve data
	buffer := buf.NewRecycleByteBuffer(65536)
	packet := make([]byte, 65536)
	for {

		n, err := tun.tunDev.Read(packet)
		if err != nil {
			klog.Error("failed to read data from tun", err)
			break
		}

		// read data from tun
		buffer.Write(packet[:n])
		for {
			// Add IP frame to byte data
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
			tun.TcpRecievePipe <- frame.ToBytes()

			klog.Infof("receive from tun, send through tunnel %s\n", frame.String())
		}
	}
	return
}

func (tun *tunIf) TunWriteLoop() {
	// buffer to write data
	buffer := buf.NewRecycleByteBuffer(65536)
	packet := make([]byte, 65536)
	for {
		// transfer data to libP2P
		//tun.TcpRecievePipe <- frame.ToBytes()
		packet = <-tun.TcpWritePipe
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

			klog.Infof("receive from tunnel, send through raw socket%s", frame.String())

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
