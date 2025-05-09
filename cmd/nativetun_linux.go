//go:build linux

package cmd

import (
	"context"
	"errors"
	"fmt"
	"log"
	"net"
	"runtime"
	"syscall"
	"time"

	"github.com/Diniboy1123/usque/api"
	"github.com/Diniboy1123/usque/config"
	"github.com/Diniboy1123/usque/internal"
	"github.com/songgao/water"
	"github.com/spf13/cobra"
	"github.com/vishvananda/netlink"
)

var nativeTunCmd = &cobra.Command{
	Use:   "nativetun",
	Short: "Expose Warp as a native TUN device",
	Long: "Linux only: Expose Warp as a native TUN device. That accepts any IP traffic." +
		" Requires root, tun.ko, and iproute2.",
	Run: func(cmd *cobra.Command, args []string) {
		if !config.ConfigLoaded {
			cmd.Println("Config not loaded. Please register first.")
			return
		}

		if runtime.GOOS != "linux" {
			cmd.Println("This command is only supported on Linux")
		}

		sni, err := cmd.Flags().GetString("sni-address")
		if err != nil {
			cmd.Printf("Failed to get SNI address: %v\n", err)
			return
		}

		privKey, err := config.AppConfig.GetEcPrivateKey()
		if err != nil {
			cmd.Printf("Failed to get private key: %v\n", err)
			return
		}
		peerPubKey, err := config.AppConfig.GetEcEndpointPublicKey()
		if err != nil {
			cmd.Printf("Failed to get public key: %v\n", err)
			return
		}

		cert, err := internal.GenerateCert(privKey, &privKey.PublicKey)
		if err != nil {
			cmd.Printf("Failed to generate cert: %v\n", err)
			return
		}

		tlsConfig, err := api.PrepareTlsConfig(privKey, peerPubKey, cert, sni)
		if err != nil {
			cmd.Printf("Failed to prepare TLS config: %v\n", err)
			return
		}

		keepalivePeriod, err := cmd.Flags().GetDuration("keepalive-period")
		if err != nil {
			cmd.Printf("Failed to get keepalive period: %v\n", err)
			return
		}
		initialPacketSize, err := cmd.Flags().GetUint16("initial-packet-size")
		if err != nil {
			cmd.Printf("Failed to get initial packet size: %v\n", err)
			return
		}

		connectPort, err := cmd.Flags().GetInt("connect-port")
		if err != nil {
			cmd.Printf("Failed to get connect port: %v\n", err)
			return
		}

		var endpoint *net.UDPAddr
		ipv6, err := cmd.Flags().GetBool("ipv6")
		if err == nil && !ipv6 {
			endpoint = &net.UDPAddr{
				IP:   net.ParseIP(config.AppConfig.EndpointV4),
				Port: connectPort,
			}
		} else {
			endpoint = &net.UDPAddr{
				IP:   net.ParseIP(config.AppConfig.EndpointV6),
				Port: connectPort,
			}
		}

		noTunnelIPv4, err := cmd.Flags().GetBool("no-tunnel-ipv4")
		if err != nil {
			cmd.Printf("Failed to get no tunnel IPv4: %v\n", err)
			return
		}

		noTunnelIPv6, err := cmd.Flags().GetBool("no-tunnel-ipv6")
		if err != nil {
			cmd.Printf("Failed to get no tunnel IPv6: %v\n", err)
			return
		}

		mtu, err := cmd.Flags().GetInt("mtu")
		if err != nil {
			cmd.Printf("Failed to get MTU: %v\n", err)
			return
		}
		if mtu != 1280 {
			log.Println("Warning: MTU is not the default 1280. This is not supported. Packet loss and other issues may occur.")
		}

		setIproute2, err := cmd.Flags().GetBool("no-iproute2")
		if err != nil {
			cmd.Printf("Failed to get no set address: %v\n", err)
			return
		}

		reconnectDelay, err := cmd.Flags().GetDuration("reconnect-delay")
		if err != nil {
			cmd.Printf("Failed to get reconnect delay: %v\n", err)
			return
		}
		dev, err := water.New(water.Config{DeviceType: water.TUN})
		if err != nil {
			log.Println("Are you root/administrator? TUN device creation usually requires elevated privileges.")
			log.Fatalf("failed to create TUN device: %v", err)
		}

		log.Printf("created TUN device: %s", dev.Name())

		if !setIproute2 {
			link, err := netlink.LinkByName(dev.Name())
			if err != nil {
				log.Fatalf("failed to get link: %v", err)
			}

			if err := netlink.LinkSetMTU(link, mtu); err != nil {
				log.Fatalf("failed to set MTU: %v", err)
			}
			if !noTunnelIPv4 {
				if err := netlink.AddrAdd(link, &netlink.Addr{
					IPNet: &net.IPNet{
						IP:   net.ParseIP(config.AppConfig.IPv4),
						Mask: net.CIDRMask(32, 32),
					}}); err != nil {
					log.Fatalf("failed to add address: %v", err)
				}
			}
			if !noTunnelIPv6 {
				if err := netlink.AddrAdd(link, &netlink.Addr{
					IPNet: &net.IPNet{
						IP:   net.ParseIP(config.AppConfig.IPv6),
						Mask: net.CIDRMask(128, 128),
					}}); err != nil {
					log.Fatalf("failed to add address: %v", err)
				}
			}
			if err := netlink.LinkSetUp(link); err != nil {
				log.Fatalf("failed to set link up: %v", err)
			}
			if !ipv6 {
				routeV4, err := getDefaultRoute(netlink.FAMILY_V4)
				if routeV4 != nil {
					addRouteV4(routeV4, endpoint, link)
				} else {
					log.Printf("failed to get default route for ipv4: %v", err)
				}
			} else {
				routeV6, err := getDefaultRoute(netlink.FAMILY_V6)

				if routeV6 != nil {
					// I don't have access to ipv6, so I can't implement it while making sure it works
				} else {
					log.Printf("failed to get default route for ipv6: %v", err)
				}
			}
			log.Println("Skipping IP address and link setup. You should set the link up manually.")
			log.Println("Config has the following IP addresses:")
			log.Printf("IPv4: %s", config.AppConfig.IPv4)
			log.Printf("IPv6: %s", config.AppConfig.IPv6)
		}

		go api.MaintainTunnel(context.Background(), tlsConfig, keepalivePeriod, initialPacketSize, endpoint, api.NewWaterAdapter(dev), mtu, reconnectDelay)

		log.Println("Tunnel established, you may now set up routing and DNS")

		select {}
	},
}

func addRouteV4(routeV4 *netlink.Route, endpoint *net.UDPAddr, link netlink.Link) {
	log.Printf("Found default route for IPv4 address: %v", routeV4)
	if err := netlink.RouteAdd(&netlink.Route{
		LinkIndex: routeV4.LinkIndex,
		Gw:        routeV4.Gw,
		Dst: &net.IPNet{
			IP:   endpoint.IP,
			Mask: net.CIDRMask(32, 32),
		},
	}); err != nil && !errors.Is(err, syscall.EEXIST) {
		log.Fatalf("failed to add route: %v", err)
	}

	if err := netlink.RouteAdd(&netlink.Route{
		LinkIndex: link.Attrs().Index,
		Scope:     netlink.SCOPE_LINK,
		Dst:       CIDR("128.0.0.0/1"),
	}); err != nil && !errors.Is(err, syscall.EEXIST) {
		log.Fatalf("failed to add route: %v", err)
	}

	if err := netlink.RouteAdd(&netlink.Route{
		LinkIndex: link.Attrs().Index,
		Scope:     netlink.SCOPE_LINK,
		Dst:       CIDR("0.0.0.0/1"),
	}); err != nil && !errors.Is(err, syscall.EEXIST) {
		log.Fatalf("failed to add route: %v", err)
	}
}

func isZeroMask(mask net.IPMask) bool {
	if mask == nil {
		return false
	}
	for _, b := range mask {
		if b != 0 {
			return false
		}
	}
	return true
}
func getDefaultRoute(family int) (*netlink.Route, error) {
	routes, err := netlink.RouteList(nil, family)
	if err != nil {
		return nil, fmt.Errorf("failed to list routes (family %d): %w", family, err)
	}
	for _, route := range routes {
		if route.Dst == nil {
			return &route, nil
		}
		if route.Dst.IP.IsUnspecified() && isZeroMask(route.Dst.Mask) {
			return &route, nil
		}
	}
	var familyStr string
	if family == netlink.FAMILY_V4 {
		familyStr = "ipv4"
	} else if family == netlink.FAMILY_V6 {
		familyStr = "ipv6"
	} else if family == netlink.FAMILY_MPLS {
		familyStr = "mpls"
	} else {
		familyStr = "all"
	}
	return nil, fmt.Errorf("no default route found (family %s)", familyStr)
}
func CIDR(cidr string) *net.IPNet {
	_, i, err := net.ParseCIDR(cidr)
	if err != nil {
		log.Fatalf("failed parse CIDR: %v", err)
	}
	return i
}
func init() {
	nativeTunCmd.Flags().IntP("connect-port", "P", 443, "Used port for MASQUE connection")
	nativeTunCmd.Flags().BoolP("ipv6", "6", false, "Use IPv6 for MASQUE connection")
	nativeTunCmd.Flags().BoolP("no-tunnel-ipv4", "F", false, "Disable IPv4 inside the MASQUE tunnel")
	nativeTunCmd.Flags().BoolP("no-tunnel-ipv6", "S", false, "Disable IPv6 inside the MASQUE tunnel")
	nativeTunCmd.Flags().StringP("sni-address", "s", internal.ConnectSNI, "SNI address to use for MASQUE connection")
	nativeTunCmd.Flags().DurationP("keepalive-period", "k", 30*time.Second, "Keepalive period for MASQUE connection")
	nativeTunCmd.Flags().IntP("mtu", "m", 1280, "MTU for MASQUE connection")
	nativeTunCmd.Flags().Uint16P("initial-packet-size", "i", 1242, "Initial packet size for MASQUE connection")
	nativeTunCmd.Flags().BoolP("no-iproute2", "I", false, "Do not set up IP addresses and do not set the link up")
	nativeTunCmd.Flags().DurationP("reconnect-delay", "r", 1*time.Second, "Delay between reconnect attempts")
	rootCmd.AddCommand(nativeTunCmd)
}
