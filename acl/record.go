package acl

import (
	"bufio"
	"fmt"
	"github.com/belowLevel/route_rule/acl/v2geo"
	"net"
	"os"
	"path"
	"path/filepath"
	"strings"
	"sync"
	"unicode"
)

type Record struct {
	file       string
	set        *v2geo.Set
	conditions []string
	operator   string
	lock       sync.Mutex
	ipReader   *IPReader
}

func (d *Record) Init() error {
	var strs []string
	if _, err := os.Stat(d.file); err != nil {
		return err
	}

	f, err := os.OpenFile(d.file, os.O_RDONLY, os.ModePerm)
	if err != nil {
		return err
	}
	defer f.Close()
	scanner := bufio.NewScanner(f)
	var count = 0
	for scanner.Scan() {
		line := scanner.Text()
		line = strings.TrimSpace(line)
		line = strings.TrimFunc(line, func(r rune) bool {
			return !unicode.IsGraphic(r)
		})
		if line == "" {
			continue
		}
		count++
		strs = append(strs, line)
	}
	if err := scanner.Err(); err != nil {
		return err
	}
	if len(strs) == 0 {
		strs = append(strs, "placeholder.placeholder")
	}
	d.set = v2geo.NewSet(strs)
	return nil
}

func (d *Record) Match(reqAddr *AddrEx) bool {
	if reqAddr.Err != nil {
		return false
	}
	if d.set == nil {
		return false
	}
	host := reqAddr.Host
	if host == "" {
		return false
	}
	ip := net.ParseIP(host)
	if ip != nil {
		return false
	}
	if d.set.Has(host) {
		return true
	}

	if reqAddr.HostInfo.IPv4 == nil {
		localResolve(reqAddr)
	}
	if reqAddr.HostInfo.IPv4 != nil {
		return d.matchISO(reqAddr.HostInfo.IPv4, host)
	}
	if reqAddr.HostInfo.IPv6 != nil {
		return d.matchISO(reqAddr.HostInfo.IPv6, host)
	}
	return false
}

func (d *Record) matchISO(ipAddress net.IP, host string) bool {
	if d.ipReader == nil {
		return false
	}
	isos := d.ipReader.LookupCode(ipAddress)
	if len(isos) == 0 {
		return false
	}
	iso := isos[0]
	var match bool
	if d.operator == "and" {
		match = true
		for _, cond := range d.conditions {
			if cond[0] == '!' {
				cond = cond[1:]
				match = strings.EqualFold(iso, cond)
				match = !match
			} else {
				match = strings.EqualFold(iso, cond)
			}
			if !match {
				return false
			}
		}
	} else if d.operator == "or" {
		match = false
		for _, cond := range d.conditions {
			if cond[0] == '!' {
				cond = cond[1:]
				match = strings.EqualFold(iso, cond)
				match = !match
			} else {
				match = strings.EqualFold(iso, cond)
			}
			if match {
				break
			}
		}
	} else {
		return false
	}

	if match {
		go func() {
			d.save(host)
		}()
		return true
	}
	return false
}

func (d *Record) Size() int {
	if d.set == nil {
		return 0
	}
	return d.set.Size()
}

func (d *Record) save(domain string) {
	d.lock.Lock()
	defer d.lock.Unlock()
	var strs = make([]string, 0, 1000)
	var seen = make(map[string]bool, 1000)
	if _, err := os.Stat(d.file); err == nil {
		f, err := os.OpenFile(d.file, os.O_RDONLY, os.ModePerm)
		if err != nil {
			return
		}
		defer f.Close()
		scanner := bufio.NewScanner(f)
		for scanner.Scan() {
			line := scanner.Text()
			line = strings.TrimSpace(line)
			line = strings.TrimFunc(line, func(r rune) bool {
				return !unicode.IsGraphic(r)
			})
			if line == "" {
				continue
			}
			if seen[line] {
				continue
			}
			strs = append(strs, line)
		}
		if err := scanner.Err(); err != nil {
			return
		}

	}
	if seen[domain] {
		return
	}
	strs = append(strs, domain)
	f, err := os.OpenFile(d.file, os.O_WRONLY|os.O_CREATE|os.O_TRUNC, os.ModePerm)
	if err != nil {
		return
	}
	defer f.Close()
	for _, v := range strs {
		f.WriteString(v + "\n")
	}
	d.Init()
}

func newRecord(addr string, ipreader *IPReader) (*Record, error) {
	suffix := addr[7:]
	idx := strings.Index(suffix, ":")
	if idx == -1 {
		return nil, fmt.Errorf("%s format invalid", addr)
	}
	file := suffix[:idx]
	suffix = suffix[idx+1:]
	idx = strings.Index(suffix, ":")
	if idx == -1 {
		return nil, fmt.Errorf("%s format invalid", file)
	}
	operator := suffix[:idx]
	suffix = suffix[idx+1:]
	if operator != "and" && operator != "or" {
		return nil, fmt.Errorf("%s format invalid", file)
	}
	conditions := strings.Split(suffix, ":")
	if len(conditions) == 0 {
		return nil, fmt.Errorf("%s format invalid", file)
	}

	ex, err := os.Executable()
	if err != nil {
		return nil, err
	}
	workDir := filepath.Dir(ex)
	fi := &Record{
		file:       path.Join(workDir, file),
		operator:   operator,
		conditions: conditions,
		ipReader:   ipreader,
	}
	err = fi.Init()
	if err != nil {
		return nil, err
	}
	return fi, nil
}
