package proc

import (
	"log"
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

type UdpTableClass uintptr

/*
typedef enum _UDP_TABLE_CLASS {
  UDP_TABLE_BASIC         ,
  UDP_TABLE_OWNER_PID     ,
  UDP_TABLE_OWNER_MODULE
} UDP_TABLE_CLASS, *PUDP_TABLE_CLASS;
*/

const (
	UDP_TABLE_BASIC UdpTableClass = iota
	UDP_TABLE_OWNER_PID
	UDP_TABLE_OWNER_MODULE
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

/*
typedef struct _MIB_UDPROW_OWNER_PID {
  DWORD dwLocalAddr;
  DWORD dwLocalPort;
  DWORD dwOwningPid;
} MIB_UDPROW_OWNER_PID, *PMIB_UDPROW_OWNER_PID;
*/

type MIB_UDPROW_OWNER_PID struct {
	localAddr uint32
	localPort uint32
	owningPid uint32
}

/*
typedef struct _MIB_UDPTABLE_OWNER_PID {
  DWORD                dwNumEntries;
  MIB_UDPROW_OWNER_PID table[ANY_SIZE];
} MIB_UDPTABLE_OWNER_PID, *PMIB_UDPTABLE_OWNER_PID;
*/

type MIB_UDPTABLE_OWNER_PID struct {
	numEntries uint32
	// nothing.
}

//private const int AF_INET = 2;

const (
	AF_INET = 2
)

const (
	FALSE = 0
	TRUE  = 1
)

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
		uintptr(AF_INET),
		uintptr(TCP_TABLE_OWNER_PID_ALL),
		uintptr(0), //Reserved
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
		uintptr(AF_INET),
		uintptr(TCP_TABLE_OWNER_PID_ALL),
		uintptr(0), //Reserved
	)
	if !ok || r1 != 0 {
		log.Printf("GetExtendedTcpTable failed: %v", err)
		return
	}

	table := (*MIB_TCPTABLE_OWNER_PID)(unsafe.Pointer(&buffer[0]))
	entCount := int(table.numEntries)

	// hdr := reflect.SliceHeader{
	// 	Data: uintptr(unsafe.Pointer(&table.entries)),
	// 	Len:  entCount,
	// 	Cap:  entCount,
	// }
	// rows := *(*[]MIB_TCPROW_OWNER_PID)(unsafe.Pointer(&hdr))
	var bp = uintptr(unsafe.Pointer(table)) + unsafe.Sizeof(table.numEntries)
	for i := 0; i < entCount; i++ {
		row := *(*MIB_TCPROW_OWNER_PID)(unsafe.Pointer(bp))
		if portState == NONE || row.state == portState {
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
		bp += unsafe.Sizeof(row)
	}
	return
}

func EnumUdpPorts() (rv []UDPPortInfo) {
	var cbSize uint32
	_, ok, _ := doCall(nGetExtendedUdpTable,
		0,
		uintptr(unsafe.Pointer(&cbSize)),
		1, //sort for me
		uintptr(AF_INET),
		uintptr(UDP_TABLE_OWNER_PID),
		uintptr(0), //reserved, and must be 0
	)
	if !ok {
		log.Printf("GetExtendedUdpTable failed")
		return
	}
	buff := make([]byte, cbSize)
	r1, ok, _ := doCall(nGetExtendedUdpTable,
		uintptr(unsafe.Pointer(&buff[0])),
		uintptr(unsafe.Pointer(&cbSize)),
		1,
		uintptr(AF_INET),
		uintptr(UDP_TABLE_OWNER_PID),
		uintptr(0), //reserved, and must be 0
	)
	if !ok || r1 != 0 {
		log.Printf("GetExtededUdpTable failed")
		return
	}

	table := (*MIB_UDPTABLE_OWNER_PID)(unsafe.Pointer(&buff[0]))
	entCount := int(table.numEntries)
	var bp = uintptr(unsafe.Pointer(table)) + unsafe.Sizeof(table.numEntries)
	for i := 0; i < entCount; i++ {
		var row = *(*MIB_UDPROW_OWNER_PID)(unsafe.Pointer(bp))
		if name, ok := GetNameForProcess(row.owningPid); ok {
			ui := UDPPortInfo{
				Name:      name,
				Pid:       row.owningPid,
				LocalIP:   translateIP(row.localAddr),
				LocalPort: fetchBigEndianUint16(row.localPort),
			}
			rv = append(rv, ui)
		}
		bp += unsafe.Sizeof(row)
	}
	return
}
