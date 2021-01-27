package main

import (
    "fmt"
    "github.com/google/gopacket"
    "github.com/google/gopacket/pcap"
    "github.com/google/gopacket/layers"
	"log"
	// "reflect" // TypeOf
	"net"
)

var (
    pcapFile string = "80211-sample.pcap"
    handle   *pcap.Handle
    err      error
)

type line struct {
	bbsid net.HardwareAddr
	power int8
	channel layers.RadioTapChannelFrequency
	beacons int32
	essid net.HardwareAddr
}

func main() {
	// handle, err = pcap.OpenLive("wlan0", 1600, true, pcap.BlockForever)
    handle, err = pcap.OpenOffline(pcapFile)
    if err != nil { 
		log.Fatal(err) 
	}
	defer handle.Close()
	
	var list []line
    packetSource := gopacket.NewPacketSource(handle, handle.LinkType())
    for packet := range packetSource.Packets() {
		// fmt.Println(packet)

		_radiotap := packet.Layer(layers.LayerTypeRadioTap)
		if _radiotap == nil {
			continue
			// fmt.Println(radiotap)
			// var version = radiotap.Version
			// var length = radiotap.Length
			// var present = radiotap.Present
			// var mac_timestamp = radiotap.TSFT
			// var flags = radiotap.Rate
			// var data_rate = radiotap.Rate
			// var Channel_flags = radiotap.ChannelFlags
			// var RX_flags = radiotap.RxFlags
			// var Antenna = radiotap.Antenna
		}
		radiotap, _ := _radiotap.(*layers.RadioTap)
		var channel_frequency = radiotap.ChannelFrequency
		var Antenna_signal = radiotap.DBMAntennaSignal
		
        _dot11 := packet.Layer(layers.LayerTypeDot11)
		if _dot11 == nil { 
			continue
		}
		dot11, _ := _dot11.(*layers.Dot11)
		var src_address = dot11.Address2
		// var sequence_number = dot11.SequenceNumber

		_dot11info := packet.Layer(layers.LayerTypeDot11InformationElement)
		if _dot11info == nil { 
			continue
		}
		dot11info, _ := _dot11info.(*layers.Dot11InformationElement)
		if dot11info.ID != layers.Dot11InformationElementIDSSID {
			continue
		}

		var exist = false
		for i, j := range list {
			if j.bbsid.String() == src_address.String() {
				list[i].power = Antenna_signal
				list[i].beacons = j.beacons + 1
				exist = true
			}
		}

		if exist == false {
			one := line{ }
			one.bbsid   = src_address
			one.power   = Antenna_signal
			one.channel = channel_frequency
			one.beacons = 1
			one.essid   = dot11info.Info
			list = append(list, one)
		}

		fmt.Println("----------------Packet----------------")
		fmt.Println("BSSID : ", src_address)
		fmt.Println("PWR : ", Antenna_signal)
		fmt.Println("Channel : ", channel_frequency)
		fmt.Printf("ESSID : %q\n", dot11info.Info)

    }
	fmt.Println(list)
}