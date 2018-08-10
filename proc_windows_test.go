package proc

import (
	"testing"
)

func TestEnump(t *testing.T) {
	for _, v := range EnumProcess() {
		t.Logf("%+q", v)
	}
}

func TestFindProcByName(t *testing.T) {
	target := "desktops.exe"
	pid := FindFirstProcessByName(target)
	if pid != 0 {
		t.Logf("Found %v: %v", target, pid)
	}
}

func TestFindProcsByName(t *testing.T) {
	target := "chrome.exe"
	pids := FindProcessesByName(target)
	for _, pid := range pids {
		t.Logf("%v: %v", target, pid)
	}
}

func TestTerminateProc(t *testing.T) {
	target := "notepad++.exe"
	pid := FindFirstProcessByName(target)
	if pid != 0 {
		TerminateProc(pid)
	} else {
		t.Logf("%v is not found", target)
	}
}
