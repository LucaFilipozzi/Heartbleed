package main

import (
    "bufio"
    "encoding/csv"
    "flag"
    "fmt"
    "net"
    "os"
    "strings"
    "sync"
    "time"

    bleed "github.com/LucaFilipozzi/Heartbleed/bleed"
    ipaddr "github.com/mikioh/ipaddr"
)

type Command struct {
    mode string
    host string
    port string
}

type Response struct {
    mode string
    host string
    port string
    result string
    reason string
}

func ProcessCommand(command Command) (response Response) {
    response.mode = command.mode
    response.host = command.host
    response.port = command.port

    var tgt bleed.Target
    tgt.Service = command.mode
    tgt.HostIp = command.host + ":" + command.port

    _, err := bleed.Heartbleed(&tgt, []byte("heartbleed.filippo.io"), true)
    if err == bleed.Safe {
        response.result = "N"
        response.reason = "SAFE"
    } else if err != nil {
        if strings.Contains(err.Error(),"Please try again") {
            response.result = "U"
            response.reason = "UNKNOWN - PLEASE TRY AGAIN"
        } else if strings.Contains(err.Error(),"i/o timeout") {
            response.result = "U"
            response.reason = "UNKNOWN - CONNECTION TIMED OUT"
        } else if strings.Contains(err.Error(),"connection refused") {
            response.result = "N"
            response.reason = "NOT VULNERABLE - CONNECTION REFUSED"
        } else {
            response.result = "E"
            response.reason = "ERROR - " + err.Error()
        }
    } else {
        response.result = "Y"
        response.reason = "VULNERABLE"
    }
    return
}

func main() {
    // parse command line arguments
    verboseFlag := flag.Bool("verbose", false, "enable verbosity on stderr")
    workersFlag := flag.Int("workers", 512, "number of workers with which to scan targets")
    flag.Usage = func() {
        fmt.Fprintf(os.Stderr, "Options:\n")
        flag.PrintDefaults()
    }
    flag.Parse()

    // set up a csv writer that outputs to stdout
    writer := csv.NewWriter(os.Stdout)

    // set up the channels for worker communication
    commandChannel := make(chan Command, 128 * *workersFlag)
    responseChannel := make(chan Response, 128 * *workersFlag)

    // set up a wait group to track the workers
    waitgrp := &sync.WaitGroup{}

    // spin up the commandChannel handlers
    for i := 0; i < *workersFlag; i++ {
        go func() {
            for command := range commandChannel {
                responseChannel <- ProcessCommand(command)
                waitgrp.Done()
            }
        }()
    }

    // spin up the responseChannel handler
    go func() {
        for {
            select {
                case response := <-responseChannel:
                    writer.Write([]string{response.result, response.mode, response.host, response.port, response.reason})
                    writer.Flush()
                case <-time.After(5 * time.Second):
                    fmt.Fprintln(os.Stderr, "timed out")
                    os.Exit(1)
            }
        }
    }()

    // process each line from standard input and issue command
    scanner := bufio.NewScanner(os.Stdin)
    for scanner.Scan() {
        line := scanner.Text()
        if strings.Count(line, ",") != 2 {
            if *verboseFlag {
                fmt.Fprintln(os.Stderr, "skipping", line, "does not parse correctly")
            }
            continue
        }

        parts := strings.Split(line, ",")
        mode := parts[0]
        spec := parts[1]
        port := parts[2]

        switch mode {
            case "ftp", "https", "imap", "pop3", "smtp":
                // do nothing - these are the valid modes
            default:
                if *verboseFlag {
                    fmt.Fprintln(os.Stderr, "skipping", line, "invalid mode")
                }
                continue
        }

        if strings.Contains(spec, "/") {
            ip, ipnet, err := net.ParseCIDR(spec)
            if err != nil {
                if *verboseFlag {
                    fmt.Fprintln(os.Stderr, "skipping", line, err)
                }
                continue
            }

            nbits, _ := ipnet.Mask.Size()
            prefix, err := ipaddr.NewPrefix(ipnet.IP, nbits)
            if err != nil {
                if *verboseFlag {
                    fmt.Fprintln(os.Stdout, "skipping", line, err)
                }
            }

            for host := range prefix.HostIter(ip) {
                if *verboseFlag {
                    fmt.Fprintln(os.Stderr, "scanning", mode, host.String(), port)
                }
                waitgrp.Add(1)
                commandChannel <- Command{mode, host.String(), port}
            }
        } else {
            if *verboseFlag {
                fmt.Fprintln(os.Stderr, "scanning", mode, spec, port)
            }
            waitgrp.Add(1)
            commandChannel <- Command{mode, spec, port}
        }
    }

    // wait for all workers to finish and clean up
    waitgrp.Wait()
    close(commandChannel)
    close(responseChannel)
    writer.Flush()
}

// vim: ft=go ts=4 sw=4 et ai sm:
