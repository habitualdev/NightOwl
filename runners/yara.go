package runners

import (
	"bytes"
	"errors"
	"fmt"
	"github.com/go-git/go-git/v5"
	"github.com/hillu/go-yara/v4"
	"log"
	"os"
	"strings"
)

func GetYaraRules(){
	if _, err := os.Stat("./rules/index.yar"); errors.Is(err, os.ErrNotExist) {
		fmt.Println("Rules directory not found, cloning https://github.com/Yara-Rules/rules")
		os.Mkdir("rules", 0755)
		git.PlainClone("rules", false, &git.CloneOptions{URL: "https://github.com/Yara-Rules/rules", Progress: os.Stdout})
	}
}


func printMatches(item string, m []yara.MatchRule, err error) string{
	if err != nil {
		log.Printf("%s: error: %s", item, err)
		return ""
	}
	if len(m) == 0 {
		return ""
	}
	buf := &bytes.Buffer{}
	fmt.Fprintf(buf, "%s: [", item)
	for i, match := range m {
		if i > 0 {
			fmt.Fprint(buf, ", ")
		}
		fmt.Fprintf(buf, "%s:%s", match.Namespace, match.Rule)
	}
	fmt.Fprint(buf, "]")
	return buf.String()

}

func runYara(fileData []byte, fileName string) string{
	c, err := yara.NewCompiler()
	if err != nil {
		log.Fatalf("Failed to initialize YARA compiler: %s", err)
	}
	f, err := os.Open("./rules/index.yar")
	c.AddFile(f,"index")

	r, err := c.GetRules()
	if err != nil {
		log.Fatalf("Failed to compile rules: %s", err)
	}
	s, _ := yara.NewScanner(r)
	var m yara.MatchRules
	err = s.SetCallback(&m).ScanMem(fileData)
	matches := printMatches(fileName, m, err)

	return matches

}

func YaraScanPcap(keyName string, data []byte){
	matches := runYara(data, keyName)
	nameSplit := strings.Split(keyName,"-")

	f, err := os.Create("./pcaps/" + nameSplit[0] + "/" + nameSplit[1] + ".yara")
	if err != nil {
		log.Fatal(err)
	}
	defer f.Close()

	f.WriteString(matches)

}