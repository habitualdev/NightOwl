package runners

import (
	"errors"
	"fmt"
	"github.com/go-git/go-git/v5"
	"github.com/zcalusic/sysinfo"
	"os"
	"os/exec"
	"regexp"
	"strings"
)

var aptScript = `apt-get install cmake make gcc g++ flex bison libpcap-dev libssl-dev python3 python3-dev swig zlib1g-dev
`
var yumScript = `yum install cmake make gcc g++ flex bison libpcap-dev libssl-dev python3 python3-dev swig zlib1g-dev
`

func GetZeek(){
	if _, err := os.Stat("./zeek"); errors.Is(err, os.ErrNotExist) {

		var si sysinfo.SysInfo
		var cmd *exec.Cmd

		si.GetSysInfo()

		ubuntuMatch, _ := regexp.Compile("ubuntu")
		popMatch, _ := regexp.Compile("Pop")
		centosMatch, _ := regexp.Compile("centos")

		println(si.OS.Name)
		fmt.Println("Attempting to detect Distro for automated dependency installation...")
		if ubuntuMatch.MatchString(si.OS.Name) || popMatch.MatchString(si.OS.Name){
			fmt.Println("Debian/Ubuntu detected, installing Debian/Ubuntu zeek dependencies")
			cmd = exec.Command("bash")
			cmd.Stdin = strings.NewReader(aptScript)
			cmd.Run()

		} else if centosMatch.MatchString(si.OS.Name){
			fmt.Println("Centos detected, installing Centos zeek dependencies")
			cmd = exec.Command("bash")
			cmd.Stdin = strings.NewReader(yumScript)
			cmd.Run()
		} else {
			fmt.Println("Distro not detected. Automated dependency installation will not be run.")
		}

		fmt.Println("Zeek not found, cloning https://github.com/zeek/zeek")
		os.Mkdir("zeek", 0755)
		git.PlainClone("zeek", false, &git.CloneOptions{URL: "https://github.com/zeek/zeek", Progress: os.Stdout,RecurseSubmodules: 1})

		os.Chdir("zeek")
		configureCmd := exec.Command("./configure")
		configureCmd.Stdout = os.Stdout
		println("Configuring")
		configureCmd.Start()
		configureCmd.Wait()
		makeCmd := exec.Command("make")
		makeCmd.Stdout = os.Stdout
		println("Making")
		makeCmd.Start()
		makeCmd.Wait()
		makeInstallCmd := exec.Command("make install")
		makeInstallCmd.Stdout = os.Stdout
		println("Installing")
		makeInstallCmd.Start()
		makeInstallCmd.Wait()

	}


}

func runZeek(keyName string){
	nameSplit := strings.Split(keyName,"-")

	pcapFile := "./pcaps/" + nameSplit[0] + "/" + nameSplit[1] + "/hoot.pcap"

	os.Chdir("./pcaps/" + nameSplit[0] + "/" + nameSplit[1])

	cmd := exec.Command("zeek", "-r", pcapFile)

	zeekLog, _ := cmd.CombinedOutput()

	cmd.Run()

	f, _ := os.OpenFile("zeek_run.log", os.O_CREATE|os.O_RDWR, 0644)
	defer f.Close()
	f.WriteString(string(zeekLog))


}

func ZeekScanPcap(keyName string){
	runZeek(keyName)
}
