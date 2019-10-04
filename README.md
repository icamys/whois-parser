# Whois parser

[![License](https://img.shields.io/badge/license-Apache%202.0-blue.svg)](LICENSE)
[![GoDoc](https://godoc.org/github.com/icamys/whois-parser?status.svg)](https://godoc.org/github.com/icamys/whois-parser)
[![Build Status](https://travis-ci.org/icamys/whois-parser.svg?branch=master)](https://travis-ci.org/icamys/whois-parser)
[![Go Report Card](https://goreportcard.com/badge/github.com/icamys/whois-parser)](https://goreportcard.com/report/github.com/icamys/whois-parser)

## Description

Extendable whois parser written in Go.

**This project is in development stage and is not ready for production systems usage.**

#### Installation

```bash
go get -u github.com/icamys/whois-parser
```

#### Usage

    package demo
    
    import (
        "encoding/json"
        "fmt"
        whoisparser "github.com/icamys/whois-parser"
    
    )
    
    func main() {
        domain := "google.com"
        whois := "Domain Name: GOOGLE.COM"
        whoisInfo, _ := whoisparser.Parse(domain, whois)
        whois2b,_ := json.Marshal(whoisInfo)
        fmt.Println(string(whois2b))
    }

## Contributing

#### Self-check

Before contributing any code please check that following commands have no warnings nor errors.

1. Check cyclomatic complexity (15 is max acceptable value):

    ```bash
    $ gocyclo -over 15 ./
    ```

1. Run tests:

    ```bash
    # Use -count=1 to disable cache usage
    $ go test -count=1 ./...
    ```

1. Lint code:

    ```
    $ golint .
    ```

#### Adding new parser for a particular TLD

Let's create new parser for TLDs `.jp` and `.co.jp`

1. Create file named `parser_jp.go` in the root directory

1. Define parser and register it:

    ```
    package whoisparser
    
    import (
        "github.com/icamys/whois-parser/internal/constants"
        "regexp"
    )
    
    // Defining new parser with regular expressions for each parsed section
    var jpParser = &Parser{
        lineMinLen: 5,
    
        errorRegex: &ParseErrorRegex{
            NoSuchDomain:     regexp.MustCompile(`No match!`),
            RateLimit:        nil,
            MalformedRequest: regexp.MustCompile(`<JPRS WHOIS HELP>`),
        },
    
        registrarRegex: &RegistrarRegex{
            CreatedDate:    regexp.MustCompile(`(?i)\[Created on] *(.+)`),
            DomainName:     regexp.MustCompile(`(?i)\[Domain Name] *(.+)`),
            DomainStatus:   regexp.MustCompile(`(?i)\[Status] *(.+)`),
            Emails:         regexp.MustCompile(`(?i)` + EmailRegex),
            ExpirationDate: regexp.MustCompile(`(?i)\[Expires on] *(.+)`),
            NameServers:    regexp.MustCompile(`(?i)\[Name Server] *(.+)`),
            UpdatedDate:    regexp.MustCompile(`(?i)\[Last Updated] *(.+)`),
        },
    
        registrantRegex: &RegistrantRegex{
            Name:         regexp.MustCompile(`(?i)\[Registrant] *(.+)`),
            Organization: regexp.MustCompile(`(?i)\[Organization] *(.+)`),
        },
    
        adminRegex: &RegistrantRegex{
            ID: regexp.MustCompile(`(?i)\[Administrative Contact] *(.+)`),
        },
    
        techRegex: &RegistrantRegex{
            ID: regexp.MustCompile(`(?i)\[Technical Contact] *(.+)`),
        },
    }
    
    // Register newly created parser for the particular TLD
    func init() {
        RegisterParser(".jp", jpParser)
    }
    ```

1. Create file named `parser_co_jp.go` in the root directory.

1. The whois for `.co.jp` extends whois for `.jp`. So we copy the `.jp` parser and extend in `init()` function:

    ```
    package whoisparser
    
    import "regexp"
    
    // copy jpParser
    var coJpParser = jpParser
    
    func init() {
        // extend coJpParser with additional regexes
        coJpParser.registrarRegex.CreatedDate = regexp.MustCompile(`\[Registered Date\] *(.+)`)
        coJpParser.registrarRegex.ExpirationDate = regexp.MustCompile(`\[State\] *(.+)`)
        coJpParser.registrarRegex.UpdatedDate = regexp.MustCompile(`\[Last Update\] *(.+)`)
    
        RegisterParser(".co.jp", coJpParser)
    }
    ```
1. Write tests. 
    1. Creating whois fixture `test/whois_co_jp.txt` with valid whois
    2. Write your parser tests in `parser_co_jp_test.go`
### Single regex for address usage
1. Set SingleRegexAddress field to true in Registrant field of your parser
    ```
       registrantRegex: &RegistrantRegex{
            SingleRegexAddress: true,
         },
    ```
1. Use regex with group naming:
    2. For ```Street``` field use ``street`` name
    2. For ```StreetExt``` field use ``StreetExt`` name
    2. For ```City``` field use ``city`` name
    2. For ```PostalCode``` field use ``postalCode`` name
    2. For ```Province``` field use ``province`` name
    2. For ```Country``` field use ``country`` name
    
    Example:
    ```
        (?ms)Registrant(?:.*?Address: *(?P<street>.*?)$.*?)\n *(?P<city>.*?)\n *(?P<postalCode>.*?)\n *(?P<province>.*?)\n *(?P<country>.*?)\n.*?Creat
    ```
    Missing groups will set by empty value.
1. Set Address field with your regex:
    ```
        registrantRegex: &RegistrantRegex{
            SingleRegexAddress: true,
            Address:            regexp.MustCompile(`(?ms)Registrant(?:.*?Address: *(?P<street>.*?)$.*?)\n *(?P<city>.*?)\n *(?P<postalCode>.*?)\n *(?P<province>.*?)\n *(?P<country>.*?)\n.*?Creat`),
           },
    ```
1. Any other address field will be ignored
    ```
        registrantRegex: &RegistrantRegex{
            SingleRegexAddress: true,
            Address:            regexp.MustCompile(`(?ms)Registrant(?:.*?Address: *(?P<street>.*?)$.*?)\n *(?P<city>.*?)\n *(?P<postalCode>.*?)\n *(?P<province>.*?)\n *(?P<country>.*?)\n.*?Creat`),
            City:               regexp.MustCompile(`City (.*)`), //Will be ignored
        },
    ```
