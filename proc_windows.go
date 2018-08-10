package proc

import (
	"log"
	"reflect"
	"strings"
	"syscall"
	"unsafe"
)

//https://docs.microsoft.com/en-us/windows/desktop/api/psapi/nf-psapi-enumprocesses

// As a matter of fact, 0 is the Idle process's PID
func FindFirstProcessByName(name string) uint32 {
	for _, v := range EnumProcess() {
		if strings.ToLower(name) == strings.ToLower(v.Name) {
			return v.Pid
		}
	}
	return 0
}

func FindProcessesByName(name string) []uint32 {
	var rv []uint32
	for _, v := range EnumProcess() {
		if strings.ToLower(name) == strings.ToLower(v.Name) {
			rv = append(rv, v.Pid)
		}
	}
	return rv
}

func GetNameForProcess(procID uint32) (name string, ok bool) {
	if 0 == procID {
		return
	}
	var handle, r1 uintptr
	var err syscall.Errno
	_ = err
	handle, ok, err = doCall(nOpenProcess,
		uintptr(PROCESS_ALL_ACCESS|PROCESS_VM_READ), //PROCESS_QUERY_INFORMATION
		uintptr(0),
		uintptr(procID),
	)
	if !ok || 0 == handle {
		// log.Printf("OpenProcess failed for <%v>: %v", procID, err)
		return
	}
	defer doCall(nCloseHandle, handle)

	var cbNeeded uint32
	var hMod uintptr
	r1, ok, err = doCall(nEnumProcessModules, handle,
		uintptr(unsafe.Pointer(&hMod)),
		uintptr(unsafe.Sizeof(hMod)),
		uintptr(unsafe.Pointer(&cbNeeded)),
	)
	if !ok || 0 == r1 {
		// log.Printf("EnumProcessModules failed: %v", err)
		ok = false
		return
	}

	bufLen := 260*2 + 100
	nameBuff := make([]uint16, bufLen)

	var aUint16 uint16
	r1, ok, _ = doCall(nGetModuleBaseNameW, handle, hMod,
		uintptr(unsafe.Pointer(&nameBuff[0])),
		uintptr(bufLen*int(unsafe.Sizeof(aUint16))),
	)
	if !ok || 0 == r1 {
		// log.Printf("GetModuleBaseName failed")
		ok = false
		return
	}
	name = syscall.UTF16ToString(nameBuff)
	return
}

func EnumProcess() []ProcInfo {
	var aUint32 uint32
	itemSize := unsafe.Sizeof(aUint32)
	totalSize := 1024 * itemSize
	buff := make([]byte, totalSize)

	var cbNeeded uint32
	var ok bool

	_, ok, _ = doCall(nEnumProcess,
		uintptr(unsafe.Pointer(&buff[0])),
		uintptr(totalSize),
		uintptr(unsafe.Pointer(&cbNeeded)),
	)

	if !ok {
		log.Printf("EnumProcess failed")
	}

	processCount := int(cbNeeded / uint32(unsafe.Sizeof(aUint32)))
	hdr := reflect.SliceHeader{
		Data: uintptr(unsafe.Pointer(&buff[0])),
		Len:  processCount,
		Cap:  processCount,
	}
	procIDs := *(*[]uint32)(unsafe.Pointer(&hdr))

	var procs []ProcInfo
	for _, procID := range procIDs {
		if name, ok := GetNameForProcess(procID); ok {
			procs = append(procs, ProcInfo{
				Name: name,
				Pid:  procID,
			})
		}
	}
	return procs
}

func TerminateProc(pid uint32) {
	handle, ok, err := doCall(nOpenProcess,
		uintptr(PROCESS_ALL_ACCESS|PROCESS_VM_READ),
		uintptr(0), //False
		uintptr(pid),
	)
	if !ok {
		log.Printf("error open process: %v", err)
		return
	}
	defer doCall(nCloseHandle, handle)

	r1, ok, err := doCall(nTerminateProcess, handle, uintptr(127))
	if !ok || 0 == r1 {
		log.Printf("TerminateProcess failed: %v", err)
		return
	}

	// Wait for all resources to release.
	r1, ok, err = doCall(nWaitForSingleObject, handle, uintptr(INFINITE))
	if !ok {
		log.Printf("WaitForSingleObject failed: %v", err)
		return
	}

	if uintptr(WAIT_OBJECT_0) != r1 {
		log.Printf("WaitForSingleObject: %x", r1)
	}
}

func GetProcessID() uint32 {
	r1, _, _ := doCall(nGetCurrentProcessId)
	return uint32(r1)
}
