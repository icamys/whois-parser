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

To try just copy and paste the following example to golang [playground](https://play.golang.org/)
(don't forget to check the "imports" flag):

```go
package main

import (
    "encoding/json"
    "fmt"
    whoisparser "github.com/icamys/whois-parser"

)

func main() {
    domain := "google.com"
    whoisRaw := "Domain Name: GOOGLE.COM"
    
    // whoisRecord is of Record type, see ./record.go
    whoisRecord := whoisparser.Parse(domain, whoisRaw)
    whois2b, _ := json.Marshal(whoisRecord)
    fmt.Println(string(whois2b))
}
```

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
- [x] info 
- [x] co
- [ ] gr (requires POST request with captcha) https://grweb.ics.forth.gr/public/whois
- [x] de 
- [x] io 
- [ ] id 
- [x] ca 
- [ ] by 
- [x] jp 
- [ ] fr 
- [ ] tw
- [ ] xn--p1ai (рф)
- [x] me
- [x] pl
- [ ] kz 
- [ ] za
- [ ] mx
- [x] it  
- [ ] eu  
- [x] tv 
- [x] xyz
- [ ] es (has restriction by whitelist, requires IP registration)
- [ ] es 
- [ ] il 
- [x] th 
- [ ] nl 
- [ ] my 
- [x] online
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
    $ golint ./...
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

### Parsing address with single regex

In some cases the whole address is provided in a way that 
it would be more convenient and performant to parse the address using only one regular expression.
For this purpose we use [regex named groups](https://www.regular-expressions.info/refext.html).

Use regex group name for particular fields:

| Field | Regex group name |
|------------|------------------|
| Street | street |
| StreetExt | streetExt |
| City | city |
| PostalCode | postalCode |
| Province | province |
| Country | country |

#### Example

Lets take a look at an example.

1. Suppose we have an address:

    ```
    Address:          Viale Del Policlinico 123/B
                      Roma
                      00263
                      RM
                      IT
    ```

2. We can craft a regular expression as follows:

    ```
    (?ms)Registrant(?:.*?Address: *(?P<street>.*?)$.*?)\n *(?P<city>.*?)\n *(?P<postalCode>.*?)\n *(?P<province>.*?)\n *(?P<country>.*?)\n.*?Creat
    ```
    
    Here all address regex groups are optional. If any group name is missing, an empty string will be assigned as value.

1. Now we assign our crafted regex to some parser structure and the address will be successfully parsed:

    ```go
    var itParser = &Parser{
        registrantRegex: &RegistrantRegex{
            Address:    regexp.MustCompile(`(?ms)Registrant(?:.*?Address: *(?P<street>.*?)$.*?)\n *(?P<city>.*?)\n *(?P<postalCode>.*?)\n *(?P<province>.*?)\n *(?P<country>.*?)\n.*?Creat`),
        },
        // ...
    }
    ```

    Parsing result:
    
    ```json
    {
        "registrant": {
            "street" : "Viale Del Policlinico 123/B",
            "city": "Roma",
            "province": "RM",
            "postal_code": "00263",
            "country": "IT"
        }
    }
    ```
   

1. Note that if the `Address` field is set, than any other address regex fields will be ignored:

    ```
    registrantRegex: &RegistrantRegex{
        Address:    regexp.MustCompile(`(?ms)Registrant(?:.*?Address: *(?P<street>.*?)$.*?)\n *(?P<city>.*?)\n *(?P<postalCode>.*?)\n *(?P<province>.*?)\n *(?P<country>.*?)\n.*?Creat`),
        City:       regexp.MustCompile(`City (.*)`), // This regex will be ignored as Address is set
    },
    ```
