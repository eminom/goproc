package proc

import (
	"syscall"
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

var (
	nEnumProcess        *syscall.Proc
	nOpenProcess        *syscall.Proc
	nGetModuleBaseNameW *syscall.Proc

	nEnumProcessModules  *syscall.Proc
	nCloseHandle         *syscall.Proc
	nTerminateProcess    *syscall.Proc
	nWaitForSingleObject *syscall.Proc
	nGetCurrentProcessId *syscall.Proc
	nGetExtendedTcpTable *syscall.Proc
	nGetExtendedUdpTable *syscall.Proc
)

func init() {
	psapi := syscall.MustLoadDLL("Psapi.dll")
	k32 := syscall.MustLoadDLL("Kernel32.dll")
	iphlp := syscall.MustLoadDLL("Iphlpapi.dll")

	nEnumProcess = psapi.MustFindProc("EnumProcesses")
	nEnumProcessModules = psapi.MustFindProc("EnumProcessModules")
	nGetModuleBaseNameW = psapi.MustFindProc("GetModuleBaseNameW")
	nOpenProcess = k32.MustFindProc("OpenProcess")
	nCloseHandle = k32.MustFindProc("CloseHandle")
	nTerminateProcess = k32.MustFindProc("TerminateProcess")
	nWaitForSingleObject = k32.MustFindProc("WaitForSingleObject")
	nGetCurrentProcessId = k32.MustFindProc("GetCurrentProcessId")

	nGetExtendedTcpTable = iphlp.MustFindProc("GetExtendedTcpTable")
	nGetExtendedUdpTable = iphlp.MustFindProc("GetExtendedUdpTable")
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
