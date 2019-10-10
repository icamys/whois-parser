# Whois parser

[![License](https://img.shields.io/badge/license-Apache%202.0-blue.svg)](LICENSE)
[![GoDoc](https://godoc.org/github.com/icamys/whois-parser?status.svg)](https://godoc.org/github.com/icamys/whois-parser)
[![Build Status](https://travis-ci.org/icamys/whois-parser.svg?branch=master)](https://travis-ci.org/icamys/whois-parser)
[![Go Report Card](https://goreportcard.com/badge/github.com/icamys/whois-parser)](https://goreportcard.com/report/github.com/icamys/whois-parser)
[![codecov](https://codecov.io/gh/icamys/whois-parser/branch/master/graph/badge.svg)](https://codecov.io/gh/icamys/whois-parser)

## Description

Extendable whois parser written in Go.

**This project is in development stage and is not ready for production systems usage. Any support will be appreciated.**

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

## Supported zones

- [x] com
- [x] ru 
- [x] net 
- [x] org 
- [x] ua 
- [x] ir 
- [x] in 
- [x] br 
- [x] tr 
- [ ] vn (requires POST request with captcha) https://www.vnnic.vn/en/whois-information?lang=en
- [x] uk 
- [ ] au 
- [ ] info 
- [ ] co
- [ ] gr (requires POST request with captcha) https://grweb.ics.forth.gr/public/whois
- [x] de 
- [ ] io 
- [ ] id 
- [ ] ca 
- [ ] by 
- [x] jp 
- [ ] fr 
- [ ] tw
- [ ] xn--p1ai (рф)
- [ ] me
- [x] pl
- [ ] kz 
- [ ] za
- [ ] mx
- [x] it  
- [ ] eu  
- [ ] tv 
- [ ] xyz
- [ ] es 
- [ ] il 
- [ ] th 
- [ ] nl 
- [ ] my 
- [ ] online
- [ ] biz
- [ ] pro 
- [ ] ar
- [ ] us
- [ ] club 
- [ ] edu
- [ ] pk (requires POST request) https://pk6.pknic.net.pk/pk5/lookup.PK
- [ ] cn 
- [ ] su
- [ ] ch  
- [ ] cl 
- [x] co.jp 

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

### Single regex for address parsing

1. Use regex with group naming:

    1. For `Street` field use `street` name
    1. For `StreetExt` field use `StreetExt` name
    1. For `City` field use `city` name
    1. For `PostalCode` field use `postalCode` name
    1. For `Province` field use `province` name
    1. For `Country` field use `country` name
    
    Example:

    ```
    (?ms)Registrant(?:.*?Address: *(?P<street>.*?)$.*?)\n *(?P<city>.*?)\n *(?P<postalCode>.*?)\n *(?P<province>.*?)\n *(?P<country>.*?)\n.*?Creat
    ```

    Here all address regex groups are optional. If any group name is missing, the value will be an empty string.

1. Set the `Address` field regex, example:

    ```
    registrantRegex: &RegistrantRegex{
        Address:    regexp.MustCompile(`(?ms)Registrant(?:.*?Address: *(?P<street>.*?)$.*?)\n *(?P<city>.*?)\n *(?P<postalCode>.*?)\n *(?P<province>.*?)\n *(?P<country>.*?)\n.*?Creat`),
    },
    ```

1. If `Address` is not nil, any other address regexes except `Address` will be ignored:

    ```
    registrantRegex: &RegistrantRegex{
        Address:    regexp.MustCompile(`(?ms)Registrant(?:.*?Address: *(?P<street>.*?)$.*?)\n *(?P<city>.*?)\n *(?P<postalCode>.*?)\n *(?P<province>.*?)\n *(?P<country>.*?)\n.*?Creat`),
        City:       regexp.MustCompile(`City (.*)`), // This regex will be ignored as Address not nil
    },
    ```
