package main

import (
	"NightOwl/runners"
	"errors"
	"fmt"
	"github.com/go-git/go-git/v5"
	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"github.com/google/gopacket/pcapgo"
	"github.com/patrickmn/go-cache"
	"log"
	"os"
	"strconv"
	"strings"
	"time"
)

var (
	subUnix = 1
	pcapBuffer = make(chan gopacket.Packet, 64)
	bufferLength int
	spcap gopacket.Packet
	writes chan int
	c = cache.New(5*time.Minute, 10*time.Minute)

)


type writePrep struct {
	PcapInfo gopacket.CaptureInfo
	PcapData []byte
}

func main() {

	if _, err := os.Stat("./rules/index.yar"); errors.Is(err, os.ErrNotExist) {
		fmt.Println("Rules directory not found, cloning https://github.com/Yara-Rules/rules")
		os.Mkdir("rules", 0755)
		git.PlainClone("rules", false, &git.CloneOptions{URL: "https://github.com/Yara-Rules/rules", Progress: os.Stdout})

		if _, err := os.Stat("./pcaps"); errors.Is(err, os.ErrNotExist) {
			os.Mkdir("./pcaps", 0755)
		}
		go writeQueue()
		go listenInterface()
		for {
			select {
			default:
				time.Sleep(1 * time.Nanosecond)
			}
		}
	}
}

func listenInterface(){
	handle, err := pcapgo.NewEthernetHandle("enp33s0f2")
	if err != nil {
		log.Fatalf("OpenEthernet: %v", err)
	}
	pkgsrc := gopacket.NewPacketSource(handle, layers.LayerTypeEthernet)
	for packet := range pkgsrc.Packets() {
		bufferLength += packet.Metadata().Length
		pcapBuffer <- packet
	}
}

func writeFile(keyName string) {

	var yaraBuffer []byte

	tempBuffer, _ := c.Get(keyName)
	nameSplit := strings.Split(keyName,"-")
	if _, err := os.Stat("./pcaps/" + nameSplit[0]); errors.Is(err, os.ErrNotExist) {
		subUnix = 1
		os.Mkdir("./pcaps/" + nameSplit[0], 0755)
		nameSplit[1] = "1"
	}

	f, err := os.Create("./pcaps/" + nameSplit[0] + "/" + nameSplit[1] + ".pcap")
	if err != nil {
		log.Fatal(err)
	}
	defer f.Close()
	pcapw := pcapgo.NewWriter(f)
	if err := pcapw.WriteFileHeader(1600, layers.LinkTypeEthernet); err != nil {
		log.Fatalf("WriteFileHeader: %v", err)
	}
	for _, wpacket := range tempBuffer.([]writePrep) {
		yaraBuffer = append(yaraBuffer, wpacket.PcapData...)
		if err := pcapw.WritePacket(wpacket.PcapInfo, wpacket.PcapData); err != nil {
			log.Fatalf("pcap.WritePacket(): %v", err)
		}
	}

	go runners.ScanPcap(keyName,yaraBuffer)

	c.Delete(keyName)
}

func writeQueue(){
	var pcaps []writePrep
	for{
		spcap = <- pcapBuffer

		pcaps = append(pcaps,writePrep{spcap.Metadata().CaptureInfo,spcap.Data()})
		if bufferLength >= 50000000 {
			keyName := strconv.Itoa(int(time.Now().Unix())) + "-" +  strconv.Itoa(subUnix)
			c.Add(keyName, pcaps, cache.DefaultExpiration)
			subUnix += 1
			go writeFile(keyName)
			bufferLength = 0
			pcaps = []writePrep{}
		}
	}


}