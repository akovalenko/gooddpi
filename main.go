package main

import (
	"bytes"
	"context"
	"flag"
	"io"
	"net"
	"net/netip"
	"os"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"syscall"
	"time"

	"log"

	"github.com/akovalenko/gooddpi/sodst"
	"github.com/akovalenko/gooddpi/xsni"
	"golang.org/x/net/proxy"
)

var transparentListenConfig = net.ListenConfig{
	Control: func(network, address string, c syscall.RawConn) error {
		var err error
		c.Control(func(fd uintptr) {
			err = syscall.SetsockoptInt(int(fd), syscall.SOL_IP,
				syscall.IP_TRANSPARENT, 1)
		})
		return err
	},
}

func domainInSet(domain string, set map[string]struct{}) bool {
	_, ok := set[""]
	if ok {
		return true // it's a catch-all domain list
	}
	if len(domain) == 0 {
		return false
	}
	if domain[len(domain)-1] == '.' {
		domain = domain[:len(domain)-1]
	}
	_, ok = set[domain]
	if ok {
		return true
	}
	dot := strings.IndexByte(domain, '.')
	if dot == -1 {
		return false
	}
	return domainInSet(domain[dot+1:], set)
}

type rule struct {
	domains map[string]struct{}
	dialer  proxy.Dialer
	name string
}

type ruleSrc struct {
	domains map[string]struct{}
	socks5  string
	name string
}

var rules atomic.Pointer[[]rule]
var ruleSources []ruleSrc

var allDomains = map[string]struct{}{
	"": {},
}

var listenPort = flag.Int("listen", 4443, "listening port (all interfaces)")
var tproxy = flag.Bool("tproxy", false, "use SO_TRANSPARENT")

func loadDomains(listName string) (map[string]struct{}, error) {
	if listName == "FOREIGN" {
		return map[string]struct{}{
			"FOREIGN": {},
		}, nil
	}
	if listName == "ANY" {
		return allDomains, nil
	}
	bs, err := os.ReadFile(listName)
	if err != nil {
		return nil, err
	}
	m := map[string]struct{}{}
	lines := bytes.Split(bs, []byte("\n"))
	for _, line := range lines {
		if len(line) > 0 {
			m[string(line)] = struct{}{}
		}
	}
	return m, nil
}

func updateRules() {
	r := []rule{}
	for _, src := range ruleSources {
		if src.socks5 != "direct" {
			conn, err := net.DialTimeout("tcp", src.socks5, time.Second)
			if err != nil {
				log.Print(err)
				continue // skip unconnectable proxy
			}
			conn.Close()
			dialer, err := proxy.SOCKS5("tcp", src.socks5, nil, proxy.Direct)
			if err != nil {
				log.Print(err)
				continue
			}
			r = append(r, rule{
				domains: src.domains,
				dialer:  dialer,
				name: src.name,
			})
		} else {
			r = append(r, rule{
				domains: src.domains,
				dialer:  proxy.Direct,
				name: src.name,
			})
		}
	}
	rules.Store(&r)
}

func main() {
	flag.Parse()

	for _, arg := range flag.Args() {
		v := strings.SplitN(arg, ":", 2)
		if len(v) != 2 {
			log.Fatal("unparsable list:route ", arg)
		}
		listName, socks5 := v[0], v[1]
		ds, err := loadDomains(listName)
		if err != nil {
			log.Fatal(err)
		}
		ruleSources = append(ruleSources, ruleSrc{
			domains: ds,
			socks5:  socks5,
			name: listName,
		})
	}
	updateRules()

	port := *listenPort
	lc := transparentListenConfig
	if !*tproxy {
		lc = net.ListenConfig{}
	}
	ln, err := lc.Listen(context.Background(),
		"tcp", "0.0.0.0:"+strconv.Itoa(port))

	if err != nil {
		log.Fatal(err)
	}

	if err != nil {
		log.Fatal(err)
	}
	for {
		conn, err := ln.Accept()
		if err != nil {
			panic(err)
		}
		domainKey := ""
		target := conn.LocalAddr()
		targetDial := target.String()
		ap, err := netip.ParseAddrPort(target.String())
		if err != nil {
			log.Fatal(err)
		}
		if ap.Port() == uint16(port) {
			targetDial, err = sodst.RealServerAddress(&conn)
			if err != nil {
				targetDial = ""
			}
		}
		if targetDial != "" {
			ap, err := netip.ParseAddrPort(targetDial)
			if err != nil {
				log.Fatal(err)
			}
			if ap.Port() != 443 {
				domainKey = "FOREIGN"
			}
		}
		go func() {
			sniName := ""
			helloBytes := &bytes.Buffer{}
			if domainKey == "" {
				conn.SetReadDeadline(time.Now().Add(5 * time.Second))
				cInfo, hb, err := xsni.PeekClientHello(conn)
				if err == nil {
					sniName = cInfo.ServerName
					if targetDial == "" {
						targetDial = net.JoinHostPort(sniName, "443")
					}
					domainKey = sniName
				}
				helloBytes = hb
				conn.SetReadDeadline(time.Time{})
			}
			dial := targetDial
			log.Print("dialing ", dial)
			var dialer proxy.Dialer = proxy.Direct
			for _, rule := range *rules.Load() {
				if domainInSet(domainKey, rule.domains) {
					dialer = rule.dialer
					log.Print("using rule: ", rule.name)
					break
				}
			}

			targetConn, err := dialer.Dial("tcp", dial)
			defer conn.Close()
			if err != nil {
				log.Print(err)
				return
			}
			defer targetConn.Close()
			var wg sync.WaitGroup
			wg.Add(1)
			go func() {
				defer wg.Done()
				defer targetConn.(*net.TCPConn).CloseWrite()
				_, err := io.Copy(targetConn, helloBytes)
				if err != nil {
					return
				}
				io.Copy(targetConn, conn)
			}()
			wg.Add(1)
			go func() {
				defer wg.Done()
				defer conn.(*net.TCPConn).CloseWrite()
				io.Copy(conn, targetConn)
			}()
			wg.Wait()
		}()
	}
}
