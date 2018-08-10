package proc

import (
	"testing"
)

func TestEnumPorts(t *testing.T) {
	for _, v := range EnumTcpPorts(NONE) {
		t.Logf("%v: <%v:%v>  - <%v:%v>", v.Name, v.LocalIP, v.LocalPort, v.RemoteIP, v.RemotePort)
	}
}
