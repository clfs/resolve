package main

import (
	"flag"
	"log"

	"github.com/clfs/resolve"
)

func main() {
	domainFlag := flag.String("domain", "", "domain to lookup")
	typeFlag := flag.String("record-type", "A", "record type to lookup")
	flag.Parse()

	var t resolve.Type

	switch *typeFlag {
	case "A":
		t = resolve.TypeA
	default:
		log.Fatalf("bad type %s", *typeFlag)
	}

	if *domainFlag == "" {
		flag.Usage()
		return
	}

	ip, err := resolve.Resolve(*domainFlag, t)
	if err != nil {
		log.Fatalf("failed lookup: %v", err)
	}

	log.Print(ip)
}
