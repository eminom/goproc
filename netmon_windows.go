package proc

import (
	"log"
	"reflect"
	"syscall"
	"unsafe"
)

type TcpTableClass uintptr

type Protocol uintptr

const (
	TCP Protocol = iota
	UDP
)

const (
	CLOSED      uint32 = 1
	LISTENING          = 2
	SYN_SENT           = 3
	SYN_RCVD           = 4
	ESTABLISHED        = 5
	FIN_WAIT1          = 6
	FIN_WAIT2          = 7
	CLOSE_WAIT         = 8
	CLOSING            = 9
	LAST_ACK           = 10
	TIME_WAIT          = 11
	DELETE_TCB         = 12
	NONE               = 0
)

const (
	TCP_TABLE_BASIC_LISTENER TcpTableClass = iota
	TCP_TABLE_BASIC_CONNECTIONS
	TCP_TABLE_BASIC_ALL
	TCP_TABLE_OWNER_PID_LISTENER
	TCP_TABLE_OWNER_PID_CONNECTIONS
	TCP_TABLE_OWNER_PID_ALL
	TCP_TABLE_OWNER_MODULE_LISTENER
	TCP_TABLE_OWNER_MODULE_CONNECTIONS
	TCP_TABLE_OWNER_MODULE_ALL
)

/*
typedef struct _MIB_TCPROW_OWNER_PID {
  DWORD dwState;
  DWORD dwLocalAddr;
  DWORD dwLocalPort;
  DWORD dwRemoteAddr;
  DWORD dwRemotePort;
  DWORD dwOwningPid;
} MIB_TCPROW_OWNER_PID, *PMIB_TCPROW_OWNER_PID;
*/

type MIB_TCPROW_OWNER_PID struct {
	state      uint32
	localAddr  uint32
	localPort  uint32
	remoteAddr uint32
	remotePort uint32
	owningPid  uint32
}

/*
typedef struct _MIB_TCPTABLE_OWNER_PID {
  DWORD                dwNumEntries;
  MIB_TCPROW_OWNER_PID table[ANY_SIZE];
} MIB_TCPTABLE_OWNER_PID, *PMIB_TCPTABLE_OWNER_PID;
*/

type MIB_TCPTABLE_OWNER_PID struct {
	numEntries uint32
	entries    byte
}

//private const int AF_INET = 2;

func EnumerateTcpPorts() []NetPortInfo {
	return EnumTcpPorts(NONE)
}

func EnumTcpPorts(portState uint32) (rv []NetPortInfo) {
	var r1 uintptr
	var err syscall.Errno
	var ok bool
	var bufSize uint32

	r1, ok, err = doCall(nGetExtendedTcpTable,
		uintptr(0),
		uintptr(unsafe.Pointer(&bufSize)),
		uintptr(1),
		uintptr(2), //AF_INET
		uintptr(TCP_TABLE_OWNER_PID_ALL),
	)
	if !ok {
		log.Printf("GetExtendedTcpTable failed: %v", err)
		return
	}

	buffer := make([]byte, bufSize)

	r1, ok, err = doCall(nGetExtendedTcpTable,
		uintptr(unsafe.Pointer(&buffer[0])),
		uintptr(unsafe.Pointer(&bufSize)),
		uintptr(1), //true
		uintptr(2), //AF_INET
		uintptr(TCP_TABLE_OWNER_PID_ALL),
	)
	if !ok || r1 != 0 {
		log.Printf("GetExtendedTcpTable failed: %v", err)
		return
	}

	table := (*MIB_TCPTABLE_OWNER_PID)(unsafe.Pointer(&buffer[0]))
	entCount := int(table.numEntries)
	hdr := reflect.SliceHeader{
		Data: uintptr(unsafe.Pointer(&table.entries)),
		Len:  entCount,
		Cap:  entCount,
	}

	rows := *(*[]MIB_TCPROW_OWNER_PID)(unsafe.Pointer(&hdr))
	for _, row := range rows {
		if portState != NONE && row.state != portState {
			continue
		}
		if name, ok := GetNameForProcess(row.owningPid); ok && name != "" {
			ni := NetPortInfo{
				Name:       name,
				LocalIP:    translateIP(row.localAddr),
				LocalPort:  fetchBigEndianUint16(row.localPort),
				RemoteIP:   translateIP(row.remoteAddr),
				RemotePort: fetchBigEndianUint16(row.remotePort),
				Pid:        row.owningPid,
			}
			rv = append(rv, ni)
		}
	}
	return
}
