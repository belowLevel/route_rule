package acl

import (
	"github.com/stretchr/testify/assert"
	"testing"
	"time"
)

func TestNewRecord(t *testing.T) {
	reader, err := NewIPInstance("v2geo/country.mmdb")
	assert.NoError(t, err)
	d, err := newRecord("record:domain.txt:and:!lan:!cn:!private", reader)
	assert.NoError(t, err)
	if err == nil {
		t.Logf("mem size %f MB", float32(d.Size())/1024/1024)
	}
	domain := "1.1.1.1"
	t.Log(d.Match(&HostInfo{
		Name: domain,
		IPv4: nil,
		IPv6: nil,
	}))
	t.Log(d.Match(&HostInfo{
		Name: domain,
		IPv4: nil,
		IPv6: nil,
	}))
	time.Sleep(5 * time.Second)
}
