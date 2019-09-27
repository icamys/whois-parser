package main

import (
	"fmt"
	whoisparser "github.com/icamys/whois-parser"
	"io/ioutil"
	"net/http"
	_ "net/http/pprof"
	"os"
	"strconv"
	"time"
)

func main() {
	go func() {
		err := http.ListenAndServe("localhost:"+strconv.Itoa(20020), nil)
		if err != nil {
			fmt.Println(err)
			os.Exit(1)
		}
	}()

	var fileBytes []byte
	var err error
	var i int

	fileBytes, err = ioutil.ReadFile("test/whois_com.txt")
	if err != nil {
		fmt.Println(err)
		os.Exit(1)
	}

	fileStr := string(fileBytes)
	iterations := 10 * 1000

	fmt.Println(fmt.Sprintf("start parsing, %d iterations", iterations))
	timeStart := time.Now()
	for i = 0; i < iterations; i += 1 {
		whoisparser.Parse("google.com", fileStr)
	}
	timeEnd := time.Now()

	fmt.Println("execution time: ", timeEnd.Sub(timeStart).String())
	fmt.Println("sleeping")
	time.Sleep(1000 * time.Second)
}
