package proc

import (
	"log"
	"reflect"
	"strings"
	"syscall"
	"unsafe"
)

//https://docs.microsoft.com/en-us/windows/desktop/api/psapi/nf-psapi-enumprocesses

var (
	nEnumProcess        *syscall.Proc
	nOpenProcess        *syscall.Proc
	nGetModuleBaseNameW *syscall.Proc

	nEnumProcessModules  *syscall.Proc
	nCloseHandle         *syscall.Proc
	nTerminateProcess    *syscall.Proc
	nWaitForSingleObject *syscall.Proc
)

const (
	STANDARD_RIGHTS_REQUIRED = 0x000F0000
	SYNCHRONIZE              = 0x00100000

	PROCESS_TERMINATE                 = (0x0001)
	PROCESS_CREATE_THREAD             = (0x0002)
	PROCESS_SET_SESSIONID             = (0x0004)
	PROCESS_VM_OPERATION              = (0x0008)
	PROCESS_VM_READ                   = (0x0010)
	PROCESS_VM_WRITE                  = (0x0020)
	PROCESS_DUP_HANDLE                = (0x0040)
	PROCESS_CREATE_PROCESS            = (0x0080)
	PROCESS_SET_QUOTA                 = (0x0100)
	PROCESS_SET_INFORMATION           = (0x0200)
	PROCESS_QUERY_INFORMATION         = (0x0400)
	PROCESS_SUSPEND_RESUME            = (0x0800)
	PROCESS_QUERY_LIMITED_INFORMATION = (0x1000)
	PROCESS_SET_LIMITED_INFORMATION   = (0x2000)

	PROCESS_ALL_ACCESS = (STANDARD_RIGHTS_REQUIRED | SYNCHRONIZE | 0xFFFF)

	INFINITE = 0xFFFFFFFF
)

const (
	WAIT_OBJECT_0  uint32 = 0
	WAIT_ABANDONED        = 0x80
	WAIT_TIMEOUT          = 0x102
	WAIT_FAILED           = 0xFFFFFFFF
)

func init() {
	psapi := syscall.MustLoadDLL("Psapi.dll")
	k32 := syscall.MustLoadDLL("Kernel32.dll")

	nEnumProcess = psapi.MustFindProc("EnumProcesses")
	nEnumProcessModules = psapi.MustFindProc("EnumProcessModules")
	nGetModuleBaseNameW = psapi.MustFindProc("GetModuleBaseNameW")
	nOpenProcess = k32.MustFindProc("OpenProcess")
	nCloseHandle = k32.MustFindProc("CloseHandle")
	nTerminateProcess = k32.MustFindProc("TerminateProcess")
	nWaitForSingleObject = k32.MustFindProc("WaitForSingleObject")
}

func doCall(elFunc *syscall.Proc, v ...uintptr) (retval uintptr, ok bool, sysErr syscall.Errno) {
	var lastErr error
	retval, _, lastErr = elFunc.Call(v...)
	sysErr, ok = lastErr.(syscall.Errno)
	if !ok || sysErr != 0 {
		return
	}
	ok = true
	return
}

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

func EnumProcess() []procInfo {

	var aUint32 uint32
	var aUint16 uint16

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

	// log.Printf("%v %v %v:%T", r1, r2, uintptr(lastErr.(syscall.Errno)), lastErr)
	processCount := int(cbNeeded / uint32(unsafe.Sizeof(aUint32)))
	// log.Printf("total: %v", processCount)
	hdr := reflect.SliceHeader{
		Data: uintptr(unsafe.Pointer(&buff[0])),
		Len:  processCount,
		Cap:  processCount,
	}
	procIDs := *(*[]uint32)(unsafe.Pointer(&hdr))

	var procs []procInfo
	for _, procID := range procIDs {

		// System idle process shall be skipped
		if 0 == procID {
			continue
		}

		handle, ok, err := doCall(nOpenProcess,
			uintptr(PROCESS_QUERY_INFORMATION|PROCESS_VM_READ),
			uintptr(0), //False
			uintptr(procID),
		)
		if !ok || 0 == handle {
			// log.Printf("OpenProcess failed for <%v>: %v", procID, err)
			continue
		}
		defer doCall(nCloseHandle, handle)

		var hMod uintptr
		r1, ok, err := doCall(nEnumProcessModules, handle,
			uintptr(unsafe.Pointer(&hMod)),
			uintptr(unsafe.Sizeof(hMod)),
			uintptr(unsafe.Pointer(&cbNeeded)),
		)
		if !ok || 0 == r1 {
			log.Printf("EnumProcessModules failed: %v", err)
			continue
		}

		bufLen := 260*2 + 100
		nameBuff := make([]uint16, bufLen)

		r1, ok, _ = doCall(nGetModuleBaseNameW, handle, hMod,
			uintptr(unsafe.Pointer(&nameBuff[0])),
			uintptr(bufLen*int(unsafe.Sizeof(aUint16))),
		)
		if !ok || 0 == r1 {
			log.Printf("GetModuleBaseName failed")
			continue
		}

		procs = append(procs, procInfo{
			Name: syscall.UTF16ToString(nameBuff),
			Pid:  procID,
		})
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
