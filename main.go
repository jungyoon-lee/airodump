package main

import (
	"flag"
	"fmt"
	"log"
	"net"
	"sort"
	"strings"
	"time"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"github.com/google/gopacket/pcap"
	"github.com/inancgumus/screen"
)

var (
	iface          string
	channel_filter int
	_bbsid_filter  string
	bbsid_filter   net.HardwareAddr

	handle *pcap.Handle
	err    error

	beacon_list []Beacon
	QoS_list    []QoS

	broadcast = net.HardwareAddr{0xff, 0xff, 0xff, 0xff, 0xff, 0xff}
)

type Beacon struct {
	bbsid       net.HardwareAddr
	power       int8
	channel     int8
	beacons     int32
	essid       string
	dst_address net.HardwareAddr
}

type QoS struct {
	bbsid   net.HardwareAddr
	station net.HardwareAddr
	power   int8
	frames  uint
	probes  string
}

func sort_beacon_list() {
	for {
		sort.Slice(beacon_list, func(i, j int) bool {
			return beacon_list[i].power > beacon_list[j].power
		})

		sort.Slice(QoS_list, func(i, j int) bool {
			return QoS_list[i].frames > QoS_list[j].frames
		})

		find_essid()

		time.Sleep(time.Second / 2)
	}
}

func show_screen() {
	for {
		screen.Clear()
		screen.MoveTopLeft()
		fmt.Println("\n BSSID              PWR    Beacons   CH   ESSID\n")
		for _, one := range beacon_list {
			fmt.Printf(" %v  %3d     %6d   %2d   %s\n", one.bbsid, one.power, one.beacons, one.channel, one.essid)
		}

		fmt.Println("\n BSSID              QoS                PWR    FRAMES   Probes\n")
		for _, one := range QoS_list {
			fmt.Printf(" %v  %v  %3d    %6d   %s\n", one.bbsid, one.station, one.power, one.frames, one.probes)
		}

		time.Sleep(time.Second)
	}
}

func find_essid() { // Beacon list -> QoS list
	for i, beacon_frame := range beacon_list {

		for j, qos_data := range QoS_list {
			if beacon_frame.bbsid.String() == qos_data.bbsid.String() {
				QoS_list[j].probes = beacon_list[i].essid
			}
		}
	}
}

func main() {
	iface := flag.String("i", "", "interface device name")
	// channel_filter := flag.Int("c", 0, "channel")
	_bbsid_filter := flag.String("bbsid", "", "bbsid_flag")

	flag.Parse()
	bbsid_filter, _ = net.ParseMAC(*_bbsid_filter)

	handle, err = pcap.OpenLive(*iface, 1600, true, pcap.BlockForever)
	if err != nil {
		log.Fatal(err)
	}
	defer handle.Close()

	go sort_beacon_list() // Goroutine
	go show_screen()

	packetSource := gopacket.NewPacketSource(handle, handle.LinkType())
	for packet := range packetSource.Packets() {
		_radiotap := packet.Layer(layers.LayerTypeRadioTap) // Radiotap Header
		if _radiotap == nil {
			continue
		}
		radiotap, _ := _radiotap.(*layers.RadioTap)
		var antenna_signal = radiotap.DBMAntennaSignal

		_dot11 := packet.Layer(layers.LayerTypeDot11)
		if _dot11 == nil {
			continue
		}
		dot11, _ := _dot11.(*layers.Dot11)
		var dst_address = dot11.Address1
		var src_address = dot11.Address2

		if bbsid_filter.String() != "" {
			if bbsid_filter.String() != dst_address.String() && bbsid_filter.String() != src_address.String() {
				continue
			}
		}

		if dot11.Type == 34 { // DataQOSData

			var exist = false
			for i, _ := range QoS_list {
				if (QoS_list[i].bbsid.String() == src_address.String() && QoS_list[i].station.String() == dst_address.String()) || (QoS_list[i].bbsid.String() == dst_address.String() && QoS_list[i].station.String() == src_address.String()) {
					QoS_list[i].power = antenna_signal
					QoS_list[i].frames = QoS_list[i].frames + 1

					exist = true
				}
			}

			if exist == false {
				one := QoS{}
				one.bbsid = src_address
				one.station = dst_address
				one.power = antenna_signal
				one.frames = 1
				one.probes = ""
				QoS_list = append(QoS_list, one)
			}

		} else if dot11.Type == 32 { // MgmtBeacon
			_dot11info := packet.Layer(layers.LayerTypeDot11InformationElement)
			if _dot11info == nil {
				continue
			}
			dot11info, _ := _dot11info.(*layers.Dot11InformationElement)
			if dot11info.ID != layers.Dot11InformationElementIDSSID {
				continue
			}

			if dst_address.String() != broadcast.String() {
				continue
			}

			// fmt.Println(dot11info.Info)

			var exist = false
			for i, j := range beacon_list {
				if beacon_list[i].bbsid.String() == src_address.String() {
					beacon_list[i].power = antenna_signal
					beacon_list[i].beacons = j.beacons + 1
					exist = true
				}
			}

			if exist == false {
				one := Beacon{}
				one.bbsid = src_address
				one.power = antenna_signal
				one.channel = 1
				one.beacons = 1

				var essid = string(dot11info.Info)

				if strings.Contains(essid, "\x00") {
					essid = "None"
				}
				one.essid = essid

				one.dst_address = dst_address
				beacon_list = append(beacon_list, one)
			}
		}
	}

}
