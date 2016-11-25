package net

import (
	"github.com/Sirupsen/logrus"
	"github.com/vishvananda/netlink"
)

type BridgeType int

const (
	WeaveBridgeName = "weave"
	DatapathName    = "datapath"

	None BridgeType = iota
	Bridge
	Fastdp
	BridgedFastdp
	Inconsistent
)

func DetectBridgeType(weaveBridgeName, datapathName string) BridgeType {
	bridge, _ := netlink.LinkByName(weaveBridgeName)
	datapath, _ := netlink.LinkByName(datapathName)

	switch {
	case bridge == nil && datapath == nil:
		return None
	case isBridge(bridge) && datapath == nil:
		return Bridge
	case isDatapath(bridge) && datapath == nil:
		return Fastdp
	case isDatapath(datapath) && isBridge(bridge):
		return BridgedFastdp
	default:
		return Inconsistent
	}
}

func isBridge(link netlink.Link) bool {
	_, isBridge := link.(*netlink.Bridge)
	return isBridge
}

func isDatapath(link netlink.Link) bool {
	switch link.(type) {
	case *netlink.GenericLink:
		return link.Type() == "openvswitch"
	case *netlink.Device:
		// Assume it's our openvswitch device, and the kernel has not been updated to report the kind.
		return true
	default:
		return false
	}
}

func DetectHairpin(portIfName string, log *logrus.Logger) {
	link, err := netlink.LinkByName(portIfName)
	if err != nil {
		log.Errorf("Unable to find link %q: %s", portIfName, err)
	}

	ch := make(chan netlink.LinkUpdate)
	// See EnsureInterface for why done channel is not passed
	if err := netlink.LinkSubscribe(ch, nil); err != nil {
		log.Errorf("Unable to subscribe to netlink updates: %s", err)
	}

	pi, err := netlink.LinkGetProtinfo(link)
	if err != nil {
		log.Errorf("Unable to get link protinfo %q: %s", portIfName, err)
	}
	if pi.Hairpin {
		log.Errorf("Hairpin mode enabled on %q", portIfName)
	}

	for up := range ch {
		if up.Attrs().Name == portIfName && up.Attrs().Protinfo != nil &&
			up.Attrs().Protinfo.Hairpin {
			log.Errorf("Hairpin mode enabled on %q", portIfName)
		}
	}
}
