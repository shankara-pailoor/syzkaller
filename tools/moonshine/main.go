package main

import (
	. "github.com/google/syzkaller/tools/moonshine/scanner"
	. "github.com/google/syzkaller/tools/moonshine/parser"
	"github.com/google/syzkaller/prog"
	"github.com/google/syzkaller/pkg/hash"
	"fmt"
	"github.com/google/syzkaller/sys"
	"os"
	"github.com/google/syzkaller/pkg/db"
	"io/ioutil"
	"path/filepath"
	"strings"
	"strconv"
)

const (
	OS = "linux"
	Arch = "amd64"
	pageSize = 4096
)

func failf(format string, a ...interface{}) {
	panic(fmt.Sprintf(format, a))
}

func main() {
	//filename := "/home/spailoor/go/src/github.com/google/syzkaller/tools/moonshine/tests/basic_open"
	filename := "/home/spailoor/linuxtp2/ltp_dup01"
	fmt.Printf("git revision: %s\n", sys.GitRevision)
	tree := Parse(filename)
	root_trace := tree.TraceMap[tree.RootPid]
	target, err := prog.GetTarget(OS, Arch)
	if err != nil {
		fmt.Printf("error getting target: %v", err.Error())
	} else {
		parsedProg, ctx, err := ParseProg(root_trace, target)
		if err != nil {
			panic("Failed to parse program")
		} else {
			ctx.State.Tracker.FillOutMemory(parsedProg)
			totalMemory := ctx.State.Tracker.GetTotalMemoryAllocations(parsedProg)
			mmapCall := ctx.Target.MakeMmap(0, uint64(totalMemory/pageSize)+1)
			calls := make([]*prog.Call, 0)
			calls = append(append(calls, mmapCall), parsedProg.Calls...)
			parsedProg.Calls = calls
		}
		fmt.Printf("Ctx cache: %#v\n", ctx.Cache)
		if err := parsedProg.Validate(); err != nil {
			panic(fmt.Sprintf("Error validating program: %s\n", err.Error()))
		}
		s_name := "serialized/" + filepath.Base(filename)
		if err := ioutil.WriteFile(s_name, parsedProg.Serialize(), 0640); err != nil {
			failf("failed to output file: %v", err)
		}
	}
}


func pack(dir, file string) {
	files, err := ioutil.ReadDir(dir)
	if err != nil {
		failf("failed to read dir: %v", err)
	}
	os.Remove(file)
	db, err := db.Open(file)
	if err != nil {
		failf("failed to open database file: %v", err)
	}
	for _, file := range files {
		data, err := ioutil.ReadFile(filepath.Join(dir, file.Name()))
		if err != nil {
			failf("failed to read file %v: %v", file.Name(), err)
		}
		var seq uint64
		key := file.Name()
		if parts := strings.Split(file.Name(), "-"); len(parts) == 2 {
			var err error

			if seq, err = strconv.ParseUint(parts[1], 10, 64); err == nil {
				key = parts[0]
			}
		}
		if sig := hash.String(data); key != sig {
			fmt.Fprintf(os.Stdout, "fixing hash %v -> %v\n", key, sig)
			key = sig
		}
		db.Save(key, data, seq)
	}
	if err := db.Flush(); err != nil {
		failf("failed to save database file: %v", err)
	}
}