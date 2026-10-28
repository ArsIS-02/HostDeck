package main

import (
	"reflect"
	"testing"
)

const tcpSample = `  sl  local_address rem_address   st tx_queue rx_queue tr tm->when retrnsmt   uid  timeout inode
   0: 00000000:0016 00000000:0000 0A 00000000:00000000 00:00000000 00000000     0        0 111 1 0000 100 0 0 10 0
   1: 0100007F:1F90 00000000:0000 0A 00000000:00000000 00:00000000 00000000     0        0 112 1 0000 100 0 0 10 0
   2: 8901A8C0:0016 0501A8C0:D2F0 01 00000000:00000000 00:00000000 00000000     0        0 113 1 0000 100 0 0 10 0
   3: 8901A8C0:A000 0802A8C0:01BB 01 00000000:00000000 00:00000000 00000000     0        0 114 1 0000 100 0 0 10 0
   4: 8901A8C0:A001 0802A8C0:01BB 01 00000000:00000000 00:00000000 00000000     0        0 115 1 0000 100 0 0 10 0
   5: 8901A8C0:A002 0802A8C0:01BB 06 00000000:00000000 00:00000000 00000000     0        0 116 1 0000 100 0 0 10 0
   6: 0100007F:A003 0100007F:1F90 01 00000000:00000000 00:00000000 00000000     0        0 117 1 0000 100 0 0 10 0
`

func TestParseProcNetTCP(t *testing.T) {
	s := parseProcNetTCP(tcpSample)
	if len(s) != 6 {
		t.Fatalf("ожидалось 6 сокетов, получено %d", len(s))
	}
	if s[0].State != "LISTEN" || s[0].LPort != 22 || s[0].Inode != "111" {
		t.Errorf("listen: %+v", s[0])
	}
	if s[2].LAddr != "192.168.1.137" || s[2].RAddr != "192.168.1.5" || s[2].RPort != 0xD2F0 {
		t.Errorf("established: %+v", s[2])
	}
}

func TestHexIPv6(t *testing.T) {
	if got := hexIP("0000000000000000FFFF000001020304"); got != "4.3.2.1" {
		// порядок слов little-endian: ::ffff:4.3.2.1 приводится к IPv4
		t.Errorf("v4-mapped: %q", got)
	}
	if got := hexIP("00000000000000000000000001000000"); got != "::1" {
		t.Errorf("loopback: %q", got)
	}
}

func TestBuildNet(t *testing.T) {
	socks := parseProcNetTCP(tcpSample)
	names := map[string]string{"111": "sshd", "113": "sshd", "114": "curl", "115": "curl"}
	procOf := func(r rawSock) (string, int) { return names[r.Inode], 1 }
	ls, cs := buildNet(socks, procOf, map[string]bool{"192.168.1.137": true})
	if len(ls) != 2 || ls[0].Port != 22 {
		t.Errorf("listen: %+v", ls)
	}
	var in, out *NetConn
	for i := range cs {
		if cs[i].Dir == "in" {
			in = &cs[i]
		} else {
			out = &cs[i]
		}
	}
	if len(cs) != 2 || in == nil || out == nil {
		t.Fatalf("conns: %+v", cs)
	}
	if in.Peer != "192.168.1.5" || in.Port != 22 || in.Proc != "sshd" {
		t.Errorf("in: %+v", *in)
	}
	if out.Peer != "192.168.2.8" || out.Port != 443 || out.N != 2 {
		t.Errorf("out (TIME_WAIT и loopback не считаются): %+v", *out)
	}
}

func TestParseARPAndRoute(t *testing.T) {
	arp := "IP address       HW type     Flags       HW address            Mask     Device\n192.168.1.1      0x1         0x2         AA:BB:CC:00:11:22     *        eth0\n192.168.1.9      0x1         0x0         00:00:00:00:00:00     *        eth0\n"
	n := parseProcARP(arp)
	if len(n) != 1 || n[0].MAC != "aa:bb:cc:00:11:22" || n[0].Dev != "eth0" {
		t.Errorf("arp: %+v", n)
	}
	rt := "Iface\tDestination\tGateway\tFlags\tRefCnt\tUse\tMetric\tMask\nwlan0\t00000000\t0101A8C0\t0003\t0\t0\t600\t00000000\nwlan0\t0001A8C0\t00000000\t0001\t0\t0\t600\t00FFFFFF\n"
	if g := parseProcRoute(rt); !reflect.DeepEqual(g, []string{"192.168.1.1"}) {
		t.Errorf("route: %v", g)
	}
	if d := parseResolvConf("# x\nnameserver 192.168.1.1\nnameserver 192.168.1.1\nnameserver ::ffff:8.8.8.8\nsearch lan\n"); !reflect.DeepEqual(d, []string{"192.168.1.1", "8.8.8.8"}) {
		t.Errorf("dns: %v", d)
	}
}

func TestParseNetMac(t *testing.T) {
	arp := "? (192.168.1.1) at a:b:c:d:e:f on en0 ifscope [ethernet]\n? (192.168.1.77) at (incomplete) on en0 ifscope [ethernet]\n? (224.0.0.251) at 1:0:5e:0:0:fb on en0 ifscope permanent [ethernet]\n"
	n := parseARPMac(arp)
	if len(n) != 2 || n[0].MAC != "0a:0b:0c:0d:0e:0f" || n[0].Dev != "en0" {
		t.Errorf("arp: %+v", n)
	}
	if g := parseRouteGet("   route to: default\n    gateway: 192.168.1.1\n  interface: en0\n"); !reflect.DeepEqual(g, []string{"192.168.1.1"}) {
		t.Errorf("route: %v", g)
	}
	if d := parseScutilDNS("resolver #1\n  nameserver[0] : 192.168.1.1\n  nameserver[1] : fe80::1%en0\n"); len(d) != 2 || d[0] != "192.168.1.1" {
		t.Errorf("dns: %v", d)
	}
	lsof := "p123\ncSafari\nf20\nn192.168.1.2:50000->93.184.216.34:443\nTST=ESTABLISHED\nf21\nn*:8080\nTST=LISTEN\np9\ncudp\nf3\nn*:53\n"
	s := parseLsof(lsof)
	if len(s) != 2 || s[0].Proc != "Safari" || s[0].RAddr != "93.184.216.34" || s[0].RPort != 443 || s[1].State != "LISTEN" || s[1].LPort != 8080 {
		t.Errorf("lsof: %+v", s)
	}
}

func TestVirtualIface(t *testing.T) {
	for n, want := range map[string]bool{"eth0": false, "en0": false, "veth1a": true, "docker0": true, "br-ab12": true, "utun3": true, "podman1": true} {
		if virtualIface(n) != want {
			t.Errorf("%s: ожидалось %v", n, want)
		}
	}
}
