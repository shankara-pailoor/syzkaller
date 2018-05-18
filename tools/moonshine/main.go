package main

import (
	. "github.com/google/syzkaller/tools/moonshine/scanner"
	. "github.com/google/syzkaller/tools/moonshine/parser"
	"github.com/google/syzkaller/prog"
	"github.com/google/syzkaller/pkg/hash"
	"fmt"
	"os"
	"github.com/google/syzkaller/pkg/db"
	"io/ioutil"
	"path/filepath"
	"strings"
	"strconv"
	"flag"
	"github.com/google/syzkaller/tools/moonshine/strace_types"
	. "github.com/google/syzkaller/tools/moonshine/logging"
	"github.com/google/syzkaller/sys"
	"path"
)

var (
	flagFile = flag.String("file", "", "file to parse")
	flagDir = flag.String("dir", "", "director to parse")
)

const (
	OS = "linux"
	Arch = "amd64"
	pageSize = 4096
)

func main() {
	fmt.Printf("git revision: %s\n", sys.GitRevision)
	flag.Parse()
	target, err := prog.GetTarget(OS, Arch)
	if err != nil {
		Failf("error getting target: %v", err.Error())
	} else {
		traces := LoadTraces()
		i := 0
		for _, trace := range(traces) {
			progs := ParseTree(trace, trace.RootPid, target)
			for _, prog_ := range(progs) {
				i += 1
				s_name := "serialized/" + filepath.Base(trace.Filename) + strconv.Itoa(i)
				if err := ioutil.WriteFile(s_name, prog_.Serialize(), 0640); err != nil {
					Failf("failed to output file: %v", err)
				}
			}
		}
		pack("serialized", "corpus.db")
	}
}

func LoadTraces() []*strace_types.TraceTree {
	ret := make([]*strace_types.TraceTree, 0)
	if *flagFile != "" {
		ret = append(ret, Parse(*flagFile))
		return ret
	} else if *flagDir != "" {
		if infos, err := ioutil.ReadDir(*flagDir); err == nil {
			for _, info := range(infos) {
				file := path.Join(*flagDir, info.Name())
				ret = append(ret, Parse(file))
			}
		} else {
			Failf("Failed to read dir: %s\n", err.Error())
		}
	}
	panic("Flag or FlagDir required")
}

func ParseTree(tree *strace_types.TraceTree, pid int64, target *prog.Target) []*prog.Prog {
	progs := make([]*prog.Prog, 0)
	parsedProg, ctx, err := ParseProg(tree.TraceMap[pid], target)
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
	progs = append(progs, parsedProg)
	for _, pid_ := range(tree.Ptree[pid]) {
		if tree.TraceMap[pid_] != nil{
			progs = append(progs, ParseTree(tree, pid_, target)...)
		}
	}
	return progs
}


func pack(dir, file string) {
	files, err := ioutil.ReadDir(dir)
	if err != nil {
		Failf("failed to read dir: %v", err)
	}
	os.Remove(file)
	db, err := db.Open(file)
	if err != nil {
		Failf("failed to open database file: %v", err)
	}
	for _, file := range files {
		data, err := ioutil.ReadFile(filepath.Join(dir, file.Name()))
		if err != nil {
			Failf("failed to read file %v: %v", file.Name(), err)
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
		Failf("failed to save database file: %v", err)
	}
}
