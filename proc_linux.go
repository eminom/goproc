package proc

import (
	"os"
)

func EnumProcess() []ProcInfo {
	return nil
}

func FindProcessesByName(name string) []uint32 {
	return nil
}

func FindFirstProcessByName(name string) uint32 {
	return 0
}

func TerminateProc(pid uint32) {}

func GetProcessID() uint32 {
	return 0
}

func GetNameForProcess(procID uint32) (name string, ok bool) {
	return "", false
}

func EnterConsole(sigCh chan<- os.Signal) {
	//NOTHING FOR LINUX
}
