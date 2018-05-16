package main

import (
	. "github.com/google/syzkaller/tools/moonshine/scanner"
	. "github.com/google/syzkaller/tools/moonshine/parser"
	"github.com/google/syzkaller/prog"
	"fmt"
	"github.com/google/syzkaller/sys"
)

const (
	OS = "linux"
	Arch = "amd64"
)

func main() {
	fmt.Printf("git revision: %s\n", sys.GitRevision)
	tree := Parse("/home/spailoor/linuxtp2/ltp_fcntl36")
	root_trace := tree.TraceMap[tree.RootPid]
	target, err := prog.GetTarget(OS, Arch)
	if err != nil {
		fmt.Printf("error getting target: %v", err.Error())
	} else {
		ParseProg(root_trace, target)
	}
}