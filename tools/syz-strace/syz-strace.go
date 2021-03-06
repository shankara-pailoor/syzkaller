package main

import (
	"errors"
	"flag"
	"fmt"
	"github.com/google/syzkaller/pkg/db"
	"github.com/google/syzkaller/pkg/hash"
	"github.com/google/syzkaller/prog"
	. "github.com/google/syzkaller/prog"
	. "github.com/google/syzkaller/tools/syz-strace/config"
	"github.com/google/syzkaller/tools/syz-strace/distiller"
	"github.com/google/syzkaller/tools/syz-strace/domain"
	. "github.com/google/syzkaller/tools/syz-strace/workload-tracer"
	. "github.com/google/syzkaller/tools/syz-structs"
	sparser "github.com/mattrco/difftrace/parser"
	"github.com/google/syzkaller/sys"
	"encoding/json"
	"io/ioutil"
	"math"
	"math/rand"
	"net"
	"os"
	"path/filepath"
	"reflect"
	"strconv"
	"strings"
	"sync"
	"github.com/google/syzkaller/syz-manager/mgrconfig"
	"github.com/google/syzkaller/tools/syz-strace/utils"
)

const (
	arch        = "amd64"
	maxLineLen  = 256 << 10
	pageSize    = 4 << 10
	maxPages    = 4 << 10
	COVER_ID    = "Cover:"
	COVER_DELIM = ","
)

var pageStartPool = sync.Pool{New: func() interface{} { return new([]uintptr) }}

type pid int64

func (p pid) String() string {
	return strconv.FormatInt(reflect.ValueOf(p).Int(), 10)
}

type Trace struct {
	rootPid pid
	ptree   map[pid][]pid
	progs   map[pid][]*sparser.OutputLine
}

func NewTrace() *Trace {
	t := new(Trace)
	t.progs = make(map[pid][]*sparser.OutputLine, 0)
	t.ptree = make(map[pid][]pid, 0)
	return t
}

func (t *Trace) Parse(lines []*sparser.OutputLine) {
	for i, line := range lines {
		fmt.Printf("PARSING LINE with pid: %v, %s\n", pid(line.Pid), line.FuncName)
		var pid_ pid = 0
		if line.Pid != 0 {
			if i == 0 {
				pid_ = t.rootPid
			} else {
				pid_ = pid(line.Pid)
			}
		}
        	if i == 0 && pid_ == 0 {
            		continue
		}
		if _, ok := t.ptree[pid_]; !ok {
			fmt.Printf("MAPAPAPAPPAPAP\n")
			t.ptree[pid_] = make([]pid, 0)
		}
		if _, ok := t.progs[pid_]; !ok {
			t.progs[pid_] = make([]*sparser.OutputLine, 0)
		}

		if line.FuncName == "clone" {
			fmt.Printf("CLONE\n")
			fmt.Printf("Result: %s\n", line.Result)
			if childPid, err := strconv.ParseInt(line.Result, 10, 64); err == nil {
				t.ptree[pid_] = append(t.ptree[pid_], pid(childPid))
				t.progs[pid(childPid)] = make([]*sparser.OutputLine, 0)
			} else {
				fmt.Printf("ERROR: %s\n", err.Error())
				panic("Error parsing pid")
			}
		}
		if ok := Unsupported[line.FuncName]; !ok {
			fmt.Printf("Appending line to pid: %v\n", pid_)
			t.progs[pid_] = append(t.progs[pid_], line)
		}
	}
	return
}

func (t *Trace) Sanitize(lines []*sparser.OutputLine) []*sparser.OutputLine {
	//sanitizedLines := lines
	sanitizedLines := make([]*sparser.OutputLine, 0)
	for i, line := range lines {
		if line.Paused {
			fmt.Printf("Paused: %s %d %d%v\n", line.FuncName, i, line.Pid, len(lines))
			for j := 0; j < len(lines)-i; j++ {
				if lines[i+j].Resumed && lines[i+j].Pid == line.Pid {
					if line.FuncName == "clone" && lines[i+j].Result == "?" {
						//The clone is going to be restarted so we should ignore
						break
					}
					lines[i].Args = append(lines[i].Args, lines[i+j].Args...)
					//If the program is unfinished it needs the result from the finished part
					lines[i].Result = lines[i+j].Result
					//Delete the resumed line
					sanitizedLines = append(sanitizedLines, line)
					break
				}
			}
		} else {
			if line.Resumed {
				continue
			}
			if line.FuncName == "clone" && line.Result == "?" {
				//The clone is going to be restarted so we should delete this line
				continue
			}
			sanitizedLines = append(sanitizedLines, line)
		}
	}
	return sanitizedLines
}

type pointer struct {
	Addr string
	Val  string
}

type returnType struct {
	Type string
	Val  string
}

var (
	flagFile      = flag.String("file", "", "file to parse")
	flagDir       = flag.String("dir", "", "directory to parse")
	flagSkip      = flag.Int("skip", 0, "how many to skip")
	flagConfig    = flag.String("config", "/etc/strace-config.json", "config file for syz strace")
	flagGetTraces = flag.Bool("trace", false, "gather traces")
	flagDistill   = flag.Bool("distill", false, "distill traces")
	flagMgrConfig = flag.String("mgr", "/root/mgr.cfg", "directory to parse")
)

func usage() {
	fmt.Fprintf(os.Stderr, "usage:\n")
	fmt.Fprintf(os.Stderr, "  ./bin/syz-strace -file filename\n")
	fmt.Fprintf(os.Stderr, "  ./bin/syz-strace -dir dirname\n")
	os.Exit(1)
}

func main() {
	fmt.Printf("git revision: %s\n", sys.GitRevision)
	var err error
	var target *Target
	flag.Parse()
	file, dir, configLocation, mgrConfigLocation := *flagFile, *flagDir, *flagConfig, *flagMgrConfig
	getTraces, distill := *flagGetTraces, *flagDistill
	/* if ((file == "" && dir == "" )|| (file != "" && dir != "")) {
			usage()
	} */
	mgrConfig, err := mgrconfig.LoadFile(mgrConfigLocation)
	if err != nil {
		panic(fmt.Sprintf("Err %s: Cannot find mgr config file: %s\n", err.Error(), mgrConfigLocation))
	}
	mgrConfig.Enable_Syscalls = make([]string, 0)
	config := NewConfig(configLocation)
	if getTraces {
		gatherTraces(config)
	}
	strace_files := make([]string, 0)
	if file != "" {
		strace_files = append(strace_files, file)
	}
	if dir == "" {
		dir = config.ParserConf.InputDirectory
	}
	if dir != "" {
		files, err := ioutil.ReadDir(dir)
		if err != nil {
			failf(err.Error())
		}
		for _, f := range files {
			strace_files = append(strace_files, filepath.Join(dir, f.Name()))
		}
	}

	fmt.Printf("strace_files: %v\n", strace_files)
	distiller_ := distiller.NewDistiller(config.DistillConf)
	os.Mkdir("serialized", 0750)
	fmt.Printf("OS: %s, ARCH: %s\n", config.ParserConf.Os, config.ParserConf.Arch)
	target, err = prog.GetTarget(config.ParserConf.Os, config.ParserConf.Arch)
	fmt.Printf("%v\n", target.ConstMap)
	if err != nil {
		s := fmt.Sprintf("Failed to parse config: %s\n", err.Error())
		panic(s)
	}
	consts := target.ConstMap
	seen_calls := make(map[string]bool)
	seeds := make(domain.Seeds, 0)
	progs := make([]*prog.Prog, 0)
	total_pids := 0
	for i, filename := range strace_files {
		if i < *flagSkip {
			continue
		}
		fmt.Fprintf(os.Stderr, "==========File %v PARSING: %v=========\n", i, filename)
		trace := NewTrace()
		straceCalls := parseStrace(filename)

		fmt.Println("==========Finished Parsing============")
		straceCalls = trace.Sanitize(straceCalls)
		trace.Parse(straceCalls)
		fmt.Fprintf(os.Stderr, "Number of pids: %d\n", len(trace.ptree))
		total_pids = total_pids + len(trace.ptree)
		for pid, childPids := range trace.ptree {
			fmt.Printf("pid: %v\n", pid)
			fmt.Printf("childPids: %v\n", childPids)
			for _, child := range childPids {
				fmt.Printf("Parent pid: %v, Child Pid: %v\n", pid, child)
			}
		}
		var parsedProg *prog.Prog
		for pid, _ := range trace.progs {
			fmt.Printf("TRACE PROGS PIDS: %v\n", pid)
			lines := trace.progs[pid]
			//if len(lines) > 250 {
			//	fmt.Printf("Pid has more than 250 calls: %v, %d", pid, len(lines))
			//	continue
			//}
			s := domain.NewState(target) /* to keep track of resources and memory */
			parsedProg, err = parse(target, lines, s, &consts, &seeds)
			if err != nil {
				fmt.Printf("Error parsing program: %s\n", err.Error())
				continue
			}

			if !distill {
				if err := s.Tracker.FillOutMemory(parsedProg); err != nil {
					fmt.Printf("Error: %s\n", err.Error())
					continue
				}
				totalMemory := s.Tracker.GetTotalMemoryAllocations(parsedProg)
				mmapCall := s.Target.MakeMmap(0, uint64(totalMemory/pageSize)+1)
				calls := make([]*prog.Call, 0)
				calls = append(append(calls, mmapCall), parsedProg.Calls...)
				parsedProg.Calls = calls
			}
			for _, call := range parsedProg.Calls {
				if _, ok := seen_calls[call.Meta.CallName]; ok {
					continue
				} else {
					seen_calls[call.Meta.CallName] = true
				}
			}
			fmt.Printf("ABOUT TO VALIDATE PROGRAM\n");
			if err := parsedProg.Validate(); err != nil {
				fmt.Printf("Error validating %vn\n", "something")
				failf(err.Error())
			}
            if progIsTooLarge(parsedProg) {
					fmt.Fprintf(os.Stderr, "Program is too large\n")
					continue
			}
			progs = append(progs, parsedProg)
			fmt.Printf("successfully parsed %v into program of length %v\n", filename, len(parsedProg.Calls))

			if !distill {
				s_name := "serialized/" + filepath.Base(filename) + pid.String()
				if err := ioutil.WriteFile(s_name, parsedProg.Serialize(), 0640); err != nil {
					failf("failed to output file: %v", err)
				}
				fmt.Printf("serialized output to %v\n", s_name)
				fmt.Printf("==============================\n\n")

			}
		}
	}
	fmt.Fprintf(os.Stderr, "===========AVERAGE PROGRAM LENGTH===================\n")
	avgLen := 0
	totalProgs := 0
	for _, prog := range progs {
		if len(prog.Calls) < 3 {
			continue
		}
		avgLen += len(prog.Calls)
		totalProgs += 1
	}
	avgLen = avgLen/totalProgs
	fmt.Fprintf(os.Stderr, "%d\n", avgLen)

	fmt.Fprintf(os.Stderr, "Total pids: %v\n", total_pids)

	fmt.Fprintf(os.Stderr, "===================Enabled Calls===================\n")
	for call, _ := range EnabledSyscalls {
		fmt.Fprintf(os.Stderr, "\"%s\",", call)
		mgrConfig.Enable_Syscalls = append(mgrConfig.Enable_Syscalls, call)
	}
	fmt.Fprintf(os.Stderr, "\n")

	/* now write mgr config back to mgrConfigLocation */
	mgrConfigJson, _ := json.Marshal(mgrConfig)
	ioutil.WriteFile(mgrConfigLocation, mgrConfigJson, 600)

	if distill {
		fmt.Fprintf(os.Stderr, "distilling using %s method\n", config.DistillConf.Type)
		distiller_.Add(seeds)
		distilled := distiller_.Distill(progs)

		for i, progd := range distilled {
            progd.Target = target
			if progIsTooLarge(progd) {
				fmt.Fprintf(os.Stderr, "Program is too large\n")
				continue
			}
			if config.DistillConf.Type != "random" {
				if err := progd.Validate(); err != nil {
					fmt.Fprintf(os.Stderr, "Error validating %v: %s\n", progd, err.Error())
					continue
					// failf(err.Error())
					// break
				}
			}

			s_name := "serialized/" + filepath.Base("distilled"+strconv.Itoa(i))
			if err := ioutil.WriteFile(s_name, progd.Serialize(), 0640); err != nil {
				failf("failed to output file: %v", err)
			}
			fmt.Printf("serialized output to %v\n", s_name)
			fmt.Printf("==============================\n\n")
		}
	}
	fmt.Println("Done, now packing into corpus.db")
	pack("serialized", "corpus.db")
}

func progIsTooLarge(prog *Prog) bool {
	buff := make([]byte, ExecBufferSize)
	if err := prog.SerializeForExec(buff, 0); err != nil {
		return true
	}
	return false
}

func gatherTraces(conf *SyzStraceConfig) {
	tracer := NewTracer(conf.CorpusGenConf)
	tracer.GenerateCorpus()
}

func parseStrace(filename string) (calls []*sparser.OutputLine) {
	var lastParsed *sparser.OutputLine
	calls = make([]*sparser.OutputLine, 0)
	f, err := os.Open(filename)
	if err != nil {
		fmt.Printf("failed to open file: %v\n", filename)
		failf(err.Error())
	}
	p := sparser.NewParser(f)
	i := 0
	for {
		line, err := p.Parse()
		if err != nil {
			if err != sparser.ErrEOF {
				fmt.Println(err.Error())
			}
			return
		}
		if line == nil {
			continue
		}
		if line.FuncName == "" && line.Result != "" && !line.Paused && !line.Resumed {
			if lastParsed == nil {
				continue
			}
			lastParsed.Cover = parseInstructions(line.Result)
		} else {
			//if _, ok := Unsupported[line.FuncName]; ok {
			//	lastParsed = nil
			//	continue
			//}
			lastParsed = line
			calls = append(calls, line)
		}
		i += 1
		fmt.Printf("I: %d\n", i)
	}
	return
}

func parse(target *Target, straceCalls []*sparser.OutputLine, s *domain.State, consts *map[string]uint64, seeds *domain.Seeds) (*Prog, error) {
	idx := -1
	prog := new(Prog)
	return_vars := make(map[returnType]Arg)

	for _, line := range straceCalls {

		seed, err := parseCall(target, line, consts, &return_vars, s, prog)
		if err != nil  {
			return nil, err
		}
		if seed == nil {
			continue
		}
		if seed.CallIdx <= idx { // seed callidx must monotonically increase
			panic(fmt.Sprintf("Seed index error, index %d\n", seed.CallIdx))
		}
		idx = seed.CallIdx
		seeds.Add(seed)
	}
	memory := s.Tracker.GetTotalMemoryAllocations(prog)
	prog.Target = target
	fmt.Printf("TOTAL Memory Needed: %d\n", memory)
	return prog, nil
}

func parseInstructions(line string) (ips []uint64) {
	/* function returns a slice of all unique IPs hit by this call
	 Used to popoulate field Seed.Cover
	*/
	uniqueIps := make(map[uint64]bool)
	line = line[1: len(line)-1]
	strippedLine := strings.TrimSpace(line)
	/*
		Instructions for a call all appear in one line of the form
		COVER_IDip1COVER_DELIMip2COVER_DELIMip3. Ex: If COVER_ID = "Cover:" and
		COVER_DELIM = "-" then it would appear as "Cover:ip1-ip2-ip3"

	*/
	instructions := strings.Split(strippedLine, COVER_ID)
	s := strings.Split(instructions[1], COVER_DELIM)
	for _, ins := range s {
        if ins == "" {
            continue
        }
		ip, err := strconv.ParseUint(strings.TrimSpace(ins), 0, 64)
		if err != nil {
			failf("failed parsing ip: %s", ins)
		}
		if _, ok := uniqueIps[ip]; !ok {
			uniqueIps[ip] = true
			ips = append(ips, ip)
		}
	}
	return
}

func parseCall(target *Target, line *sparser.OutputLine, consts *map[string]uint64,
	return_vars *map[returnType]Arg, s *domain.State, prog_ *Prog) (*domain.Seed, error) {
	if _, ok := Unsupported[line.FuncName]; ok {
		fmt.Printf("Found unsupported call: %s in prog: %v\n", line.FuncName, prog_) // don't parse unsupported syscalls
		return nil, nil
	}

	if _, ok := VMACall[line.FuncName]; ok {
		//return nil, nil
		EnabledSyscalls[line.FuncName] = true
		if strings.Compare(line.FuncName, "mmap") == 0 {
			seed := parseMmap(line, prog_, s, return_vars)
			prog_.Calls = append(prog_.Calls, seed.Call)
			return seed, nil
		} else if strings.Compare(line.FuncName, "mprotect") == 0 {
			seed := parseMprotect(line, prog_, s, return_vars)
			prog_.Calls = append(prog_.Calls, seed.Call)
			return seed, nil
		}  else if strings.Compare(line.FuncName, "munmap") == 0 {
			seed := parseMunmap(line, prog_, s, return_vars)
			prog_.Calls = append(prog_.Calls, seed.Call)
			return seed, nil
		} else if strings.Compare(line.FuncName, "msync") == 0 {
			seed := parseMsync(line, prog_, s, return_vars)
			prog_.Calls = append(prog_.Calls, seed.Call)
			return seed, nil
		} else if strings.Compare(line.FuncName, "remap_file_pages") == 0 {
			seed := parseRemapFilePages(line, prog_, s, return_vars)
			prog_.Calls = append(prog_.Calls, seed.Call)
			return seed, nil
		} else if strings.Compare(line.FuncName, "mremap") == 0 {
			seed := parseMremap(line, prog_, s, return_vars)
			prog_.Calls = append(prog_.Calls, seed.Call)
			return seed, nil
		} else if strings.Compare(line.FuncName, "shmat") == 0 {
			seed := parseShmat(line, prog_, s, return_vars)
			prog_.Calls = append(prog_.Calls, seed.Call)
			return seed, nil
		}  else if strings.Compare(line.FuncName, "mlock") == 0 {
			seed := parseMlock(line, prog_, s, return_vars)
			prog_.Calls = append(prog_.Calls, seed.Call)
			return seed, nil
		} else if strings.Compare(line.FuncName, "munlock") == 0 {
			seed := parseMUnlock(line, prog_, s, return_vars)
			prog_.Calls = append(prog_.Calls, seed.Call)
			return seed, nil
		} else if strings.Compare(line.FuncName, "madvise") == 0 {
			seed := parseMadvise(line, prog_, s, return_vars)
			prog_.Calls = append(prog_.Calls, seed.Call)
			return seed, nil
		}
		return nil, nil

	}

	/* adjust functions to fit syzkaller standards */
	skip := process(target, line, consts, return_vars)
	if skip {
		return nil, nil
	}
	meta := target.SyscallMap[line.FuncName]
	if meta == nil {
		fmt.Printf("unknown syscall %v\n", line.Unparse())
		return nil, nil
	}
	//fmt.Printf("unknown syscall %v\n", line.FuncName)
	//continue

	fmt.Println("---------Parsing line-----------")
	fmt.Println("signal")
	fmt.Printf("Signal: %v\n", line.Signal)
	fmt.Printf("FuncName: %v\n", line.FuncName)
	fmt.Printf("Args: %v\n", line.Args)
	for j, arg := range line.Args {
		fmt.Printf("\narg %v: %v\n", j, arg)
	}
	fmt.Printf("Result: %v\n", line.Result)
	fmt.Println(line.Unparse())

	c := &Call{
		Meta: meta,
		Ret:  returnArg(meta.Ret),
	}
	s.CurrentCall = c
	var calls []*Call
	var strace_arg string
	progLen := len(prog_.Calls)
	for i, typ := range meta.Args {
		if i < len(line.Args) {
			strace_arg = line.Args[i]
		} else {
			fmt.Printf("arg %v %v not present, using nil\n", i, typ.Name())
			strace_arg = "nil"
			//failf("arg %v %v not present for call: %s\n", i, typ.Name(), line.FuncName)
		}
		parsedArg, calls1, err := parseArg(typ, strace_arg, consts, return_vars, line, s)
		if err != nil {
			return nil, err
		}
		c.Args = append(c.Args, parsedArg)
		calls = append(calls, calls1...)
	}


	calls = append(calls, c)

	// store the return value if we had a valid return
	if line.Result != "?" && meta.Ret != nil {
		return_var := returnType{
			getType(meta.Ret),
			line.Result,
		}
		cache(return_vars, return_var, c.Ret, true)
	}

	postProcess(line, c, prog_, s)
	// add calls to our program

	for _, c := range calls {
		// TODO: sanitize c?
		fmt.Printf("Analyzing Call: %v %s\n", c, c.Meta.CallName)
		s.Analyze(c)
		prog_.Calls = append(prog_.Calls, c)
	}
	dependsOn := make(map[*prog.Call]int, 0)
	for i := 0; i < len(calls)-1; i++ {
		dependsOn[calls[i]] = progLen + i
	}
	fmt.Println("\n---------done parsing line--------\n")
	return domain.NewSeed(c, s, dependsOn, prog_, len(prog_.Calls)-1, line.Cover), nil
}

func postProcess(line *sparser.OutputLine, call *Call, prog_ *prog.Prog, state *domain.State) {
	switch line.FuncName {
	case "shmget":
		//Add request id and size to the memory tracker
		if shmid, err := strconv.ParseUint(line.Result, 0, 64); err == nil {
			if size, err := strconv.ParseUint(line.Args[1], 0, 64); err == nil {
				state.Tracker.AddShmRequest(call, shmid, size)
			}
		}
	}
}

func parseMmap(line *sparser.OutputLine,  prog_ *prog.Prog, state *domain.State, return_vars *map[returnType]Arg) *domain.Seed {
	fmt.Printf("Call: %s\n", line.FuncName)
	for i, _ := range line.Args {
		fmt.Printf("Arg: %d: %v\n", i, line.Args[i])
	}
	if (len(line.Args) < 4) {
		return nil
	}
	meta := state.Target.SyscallMap[line.FuncName]
	call := &prog.Call{
		Meta: meta,
		Ret: returnArg(meta.Ret),
	}
	fmt.Printf("Call: %v\n", call)
	start := uint64(0)
	length := uint64(0)
	prot := uint64(0)
	flags := uint64(0)
	var fd Arg;

	if meta == nil {
		fmt.Printf("unknown syscall %v\n", line.Unparse())
		return nil
	}

	if strings.Contains(line.Args[0], "NULL") {
		//We have an anonymous map

		if res, err := strconv.ParseUint(line.Result, 0, 64); err == nil {
			start = res

			fmt.Printf("start: %d\n", start)
		}
	} else {
		//This is a mmap fixed
		if res, err := strconv.ParseUint(line.Args[0], 0, 64); err == nil {
			start = res
			fmt.Printf("start: %d\n", start)
		}
	}

	if res, err := strconv.ParseUint(line.Args[1], 0, 64); err == nil {
		length = res
		fmt.Printf("Length: %d\n", length)
	}

	for _, prot_field := range strings.Split(line.Args[2], "|") {
		fmt.Printf("Protection: %s\n", prot_field)
		prot |= state.Target.ConstMap[prot_field]
	}

	for _, flag := range strings.Split(line.Args[3], "|") {
		fmt.Printf("Field: %s\n", flag)
		flags |= state.Target.ConstMap[flag]
	}
	flags |= state.Target.ConstMap["MAP_FIXED"]
	key := returnType {
		Type: "ResourceType" + "fd",
		Val: line.Args[4],
	}
	if res, ok := (*return_vars)[key]; ok {
		fmt.Printf("FOUND RESULT: %v\n", res)
		//fd = res
		fd = resultArg(res.Type(), res, res.Type().Default())
	} else {
		fd = MakeResultArg(meta.Args[4], nil, ^uint64(0))
	}
	fmt.Printf("LENGTH/PAGESIZE: %d\n", length/pageSize)
	if length % pageSize > 0 {
		length = (length/pageSize + 1)*pageSize //Make length page aligned
	}

	call.Args = []Arg {
		prog.MakePointerArg(meta.Args[0], start, 0, length/pageSize, nil),
		prog.MakeConstArg(meta.Args[1], length),
		prog.MakeConstArg(meta.Args[2], prot),
		prog.MakeConstArg(meta.Args[3], flags),
		fd,
		prog.MakeConstArg(meta.Args[5], 0),
	}
	state.Tracker.CreateMapping(call, len(prog_.Calls), call.Args[0], start, start+length) //All mmaps have fixed mappings in syzkaller
	return domain.NewSeed(call, state, nil, prog_, len(prog_.Calls), line.Cover)
}

func parseMprotect(line *sparser.OutputLine, prog_ *prog.Prog, state *domain.State, return_vars *map[returnType]Arg) *domain.Seed {
	fmt.Printf("Call: %s\n", line.FuncName)
	for i, _ := range line.Args {
		fmt.Printf("Arg: %d: %v\n", i, line.Args[i])
	}
	meta := state.Target.SyscallMap[line.FuncName]
	call := &prog.Call{
		Meta: meta,
		Ret: returnArg(meta.Ret),
	}
	start := uint64(0)
	length := uint64(0)
	prot := uint64(0)
	var dependsOn map[*prog.Call]int = nil


	if res, err := strconv.ParseUint(line.Args[0], 0, 64); err == nil {
		start = res
		fmt.Printf("Start: %d\n", length)
	} else if res, err := strconv.ParseInt(line.Args[0], 0, 64); err == nil{
		if res < 0 {
			start = ^uint64(0)
		}
	}

	if res, err := strconv.ParseUint(line.Args[1], 0, 64); err == nil {
		length = res
	}

	for _, prot_field := range strings.Split(line.Args[2], "|") {
		fmt.Printf("Protection: %s\n", prot_field)
		prot |= state.Target.ConstMap[prot_field]
	}

	addrArg := prog.MakePointerArg(meta.Args[0], start/pageSize, 0, 1, nil)
	if mapping := state.Tracker.FindLatestOverlappingVMA(start); mapping != nil {
		dependsOn = make(map[*prog.Call]int, 0)
		dependsOn[mapping.GetCall()] = mapping.GetCallIdx()
		for _, dep := range mapping.GetUsedBy() {
			dependsOn[prog_.Calls[dep.Callidx]] = dep.Callidx
		}
		dep := domain.NewMemDependency(len(prog_.Calls), addrArg, start, start+length)
		mapping.AddDependency(dep)

	}

	call.Args = []Arg {
		addrArg,
		prog.MakeConstArg(meta.Args[1], length),
		prog.MakeConstArg(meta.Args[2], prot),
	}


	return domain.NewSeed(call, state, dependsOn, prog_, len(prog_.Calls), line.Cover)
}

func parseMunmap(line *sparser.OutputLine, prog_ *prog.Prog, state *domain.State, return_vars *map[returnType]Arg) *domain.Seed {
	for i, arg := range line.Args {
		fmt.Printf("Munmap Arg: %d %s\n", i, arg)
	}
	start := uint64(0)
	length := uint64(0)
	var dependsOn map[*Call]int = nil

	meta := state.Target.SyscallMap[line.FuncName]
	call := &prog.Call{
		Meta: meta,
		Ret: returnArg(meta.Ret),
	}

	if res, err := strconv.ParseUint(line.Args[0], 0, 64); err == nil {
		start = res
		fmt.Printf("Start: %d\n", length)
	} else {
		panic(fmt.Sprintf("Failed to parse address in munmap: %s\n", line.Args[0]))
	}

	if res, err := strconv.ParseUint(line.Args[1], 0, 64); err == nil {
		length = res
		fmt.Printf("Length: %d\n", length)
	} else {
		panic(fmt.Sprintf("Failed to length in munmap: %s\n", line.Args[1]))
	}
	addrArg := prog.MakePointerArg(meta.Args[0], start/pageSize, 0, 1, nil)
	if mapping := state.Tracker.FindLatestOverlappingVMA(start); mapping != nil {
		dependsOn = make(map[*prog.Call]int, 0)
		dependsOn[mapping.GetCall()] = mapping.GetCallIdx()
		for _, dep := range mapping.GetUsedBy() {
			dependsOn[prog_.Calls[dep.Callidx]] = dep.Callidx
		}
		dep := domain.NewMemDependency(len(prog_.Calls), addrArg, start, start+length)
		mapping.AddDependency(dep)
	}

	call.Args = []Arg {
		addrArg,
		prog.MakeConstArg(meta.Args[1], length),
	}
	return domain.NewSeed(call, state, dependsOn, prog_, len(prog_.Calls), line.Cover)
}

func parseMsync(line *sparser.OutputLine, prog_ *prog.Prog, state *domain.State, return_vars *map[returnType]Arg) *domain.Seed {
	fmt.Printf("Call: %s\n", line.FuncName)
	for i, _ := range line.Args {
		fmt.Printf("Arg: %d: %v\n", i, line.Args[i])
	}
	meta := state.Target.SyscallMap[line.FuncName]
	call := &prog.Call{
		Meta: meta,
		Ret: returnArg(meta.Ret),
	}
	start := uint64(0)
	length := uint64(0)
	flags := uint64(0)
	var dependsOn map[*Call]int = nil


	if res, err := strconv.ParseUint(line.Args[0], 0, 64); err == nil {
		start = res
		fmt.Printf("Start: %d\n", start)
	} else {
		panic(fmt.Sprintf("Failed to parse address in msync: %s\n", line.Args[0]))
	}

	if res, err := strconv.ParseUint(line.Args[1], 0, 64); err == nil {
		length = res
	} else {
		panic(fmt.Sprintf("Failed to parse length in mysnc: %s\n", line.Args[1]))
	}

	for _, prot_field := range strings.Split(line.Args[2], "|") {
		fmt.Printf("Protection: %s\n", prot_field)
		flags |= state.Target.ConstMap[prot_field]
	}

	addrArg := prog.MakePointerArg(meta.Args[0], start/pageSize, 0, 1, nil)

	if mapping := state.Tracker.FindLatestOverlappingVMA(start); mapping != nil {
		fmt.Printf("Found mapping: %v\n", mapping)
		dependsOn = make(map[*prog.Call]int, 0)
		dependsOn[mapping.GetCall()] = mapping.GetCallIdx()
		for _, dep := range mapping.GetUsedBy() {
			dependsOn[prog_.Calls[dep.Callidx]] = dep.Callidx
		}
		dep := domain.NewMemDependency(len(prog_.Calls), addrArg, start, start+length)
		mapping.AddDependency(dep)
	}

	call.Args = []Arg {
		addrArg,
		prog.MakeConstArg(meta.Args[1], length),
		prog.MakeConstArg(meta.Args[2], flags),
	}
	return domain.NewSeed(call, state, dependsOn, prog_, len(prog_.Calls), line.Cover)
}

func parseRemapFilePages(line *sparser.OutputLine,  prog_ *prog.Prog, state *domain.State, return_vars *map[returnType]Arg) *domain.Seed {
	fmt.Printf("Call: %s\n", line.FuncName)
	for i, _ := range line.Args {
		fmt.Printf("Arg: %d: %v\n", i, line.Args[i])
	}
	start := uint64(0)
	length := uint64(0)
	prot := uint64(0)
	pgoff := uint64(0)
	flags := uint64(0)
	var dependsOn map[*Call]int = nil

	meta := state.Target.SyscallMap[line.FuncName]
	call := &prog.Call{
		Meta: meta,
		Ret: returnArg(meta.Ret),
	}

	if res, err := strconv.ParseUint(line.Args[0], 0, 64); err == nil {
		start = res
		fmt.Printf("Start: %d\n", start)
	} else {
		panic("Failed to parse address in remap_file_pages")
	}

	if res, err := strconv.ParseUint(line.Args[1], 0, 64); err == nil {
		length = res
	} else {
		panic("Failed to parse length in remap_file_pages")
	}

	if length % pageSize > 0 {
		//See man pages for mremap. If the length is not page aligned the kernel rounds down
		//We will round down to simplify tracking
		length = (length/pageSize)*pageSize
	}

	for _, prot_field := range strings.Split(line.Args[2], "|") {
		fmt.Printf("Protection: %s\n", prot_field)
		prot |= state.Target.ConstMap[prot_field]
	}

	if res, err := strconv.ParseUint(line.Args[3], 0, 64); err == nil {
		pgoff = res
	} else {
		panic("Failed to parse pgoff argument in remap_file_pages")
	}

	for _, flag_field := range strings.Split(line.Args[4], "|") {
		fmt.Printf("Protection: %s\n", flag_field)
		flags |= state.Target.ConstMap[flag_field]
	}


	addrArg := prog.MakePointerArg(meta.Args[0], start/pageSize, 0, 1, nil)

	if mapping := state.Tracker.FindLatestOverlappingVMA(start); mapping != nil {
		fmt.Printf("Found mapping: %v\n", mapping)
		dependsOn = make(map[*prog.Call]int, 0)
		dependsOn[mapping.GetCall()] = mapping.GetCallIdx()
		for _, dep := range mapping.GetUsedBy() {
			dependsOn[prog_.Calls[dep.Callidx]] = dep.Callidx
		}
		dep := domain.NewMemDependency(len(prog_.Calls), addrArg, start, start+length)
		mapping.AddDependency(dep)
	}

	call.Args = []Arg {
		addrArg,
		prog.MakeConstArg(meta.Args[1], length),
		prog.MakeConstArg(meta.Args[2], prot),
		prog.MakeConstArg(meta.Args[3], pgoff),
		prog.MakeConstArg(meta.Args[4], flags),

	}
	return domain.NewSeed(call, state, dependsOn, prog_, len(prog_.Calls), line.Cover)
}

func parseMremap(line *sparser.OutputLine,  prog_ *prog.Prog, state *domain.State, return_vars *map[returnType]Arg) *domain.Seed {
	/*
	 * Mremap either has 4 arguments or 5. If it has 5 then it is trying to map to a fixed address
	 * Syzkaller requires the remapping to be fixed so make sure to add MREMAP_FIXED flag to the flag
	 */
	fmt.Printf("Call: %s\n", line.FuncName)
	for i, _ := range line.Args {
		fmt.Printf("Arg: %d: %v\n", i, line.Args[i])
	}
	fmt.Printf("RET: %s\n", line.Result)
	old_addr := uint64(0)
	remapped_addr := uint64(maxPages*pageSize) //Should be maximum address
	old_size := uint64(0)
	new_size := uint64(0)
	flags := uint64(0)
	var dependsOn map[*Call]int = nil

	meta := state.Target.SyscallMap[line.FuncName]
	call := &prog.Call{
		Meta: meta,
		Ret: returnArg(meta.Ret),
	}

	fmt.Printf("remapped addr start: %d\n", remapped_addr)
	//For mremap the first argument must be an address
	if res, err := strconv.ParseUint(line.Args[0], 0, 64); err == nil {
		old_addr = res
		fmt.Printf("Start: %d\n", old_addr)
	} else {
		panic("Failed to parse address in mremap")
	}

	//Getting old size of VMA
	if res, err := strconv.ParseUint(line.Args[1], 0, 64); err == nil {
		old_size = res
	} else {
		panic("Failed to parse old size in mremap_pages")
	}

	//Getting new size of VMA
	if res, err := strconv.ParseUint(line.Args[2], 0, 64); err == nil {
		new_size = res
		fmt.Printf("new size: %d\n", new_size)
	} else {
		panic("Failed to parse new size in mremap")
	}


	for _, flag_field := range strings.Split(line.Args[3], "|") {
		flags |= state.Target.ConstMap[flag_field]
	}

	flags |= state.Target.ConstMap["MREMAP_FIXED"]
	if len(line.Args)  < 5 {
		 //We have an anonymous map
		if res, err := strconv.ParseUint(line.Result, 0, 64); err == nil {
			remapped_addr = res

			fmt.Printf("remapped addr: %d\n", remapped_addr)
		}
	} else {
		//This is a mmremap fixed
		if res, err := strconv.ParseUint(line.Args[4], 0, 64); err == nil {
			remapped_addr = res
			fmt.Printf("start: %d\n", remapped_addr)
		} else {
			panic("Failed to parse address for mmap fixed")
		}
	}



	for _, flag_field := range strings.Split(line.Args[3], "|") {
		flags |= state.Target.ConstMap[flag_field]
	}

	fmt.Printf("remapped addr/pageSize: %d\n", remapped_addr/pageSize)
	oldAddrArg := prog.MakePointerArg(meta.Args[0], old_addr/pageSize, 0, 1, nil)
	newAddrArg := prog.MakePointerArg(meta.Args[4], remapped_addr, 0, 1, nil)

	//Add this mmap to the dependency list of the old mapping
	if mapping := state.Tracker.FindLatestOverlappingVMA(old_addr); mapping != nil {
		dependsOn = make(map[*prog.Call]int, 0)
		dependsOn[mapping.GetCall()] = mapping.GetCallIdx()
		for _, dep := range mapping.GetUsedBy() {
			dependsOn[prog_.Calls[dep.Callidx]] = dep.Callidx
		}
		dep := domain.NewMemDependency(len(prog_.Calls), oldAddrArg, old_addr, old_addr)
		mapping.AddDependency(dep)
	}

	//Create new mapping for remapped address.
	call.Args = []Arg{
		oldAddrArg,
		prog.MakeConstArg(meta.Args[1], old_size),
		prog.MakeConstArg(meta.Args[2], new_size),
		prog.MakeConstArg(meta.Args[3], flags),
		newAddrArg,
	}

	state.Tracker.CreateMapping(call, len(prog_.Calls), call.Args[4], remapped_addr, remapped_addr + new_size)
	return domain.NewSeed(call, state, dependsOn, prog_, len(prog_.Calls), line.Cover)
}

func parseShmat(line *sparser.OutputLine,  prog_ *prog.Prog, state *domain.State, return_vars *map[returnType]Arg) *domain.Seed {
	/*
	 * Shmat will create a shared memory map which we should track.
	 * If the second argument is NULL then shmat will create the memory map and
	 * store it at that address if successful.
	 */

	addr := uint64(0)
	flags := uint64(0)
	shmid := uint64(0)
	var fd Arg

	fmt.Printf("Call: %s\n", line.FuncName)
	for i, _ := range line.Args {
		fmt.Printf("Arg: %d: %v\n", i, line.Args[i])
	}


	meta := state.Target.SyscallMap[line.FuncName]
	call := &prog.Call{
		Meta: meta,
		Ret: returnArg(meta.Ret),
	}

	return_var := returnType {
		Type: getType(meta.Args[0]),
		Val: line.Args[0],
	}

	/* Get shared map id.
	 * Check to see if it has been cached. If it hasn't then we are likely running a call that failed.
	 * but it may still give interesting coverage so we parse with the same id we get from strace
	 */

	if ret, ok := (*return_vars)[return_var]; ok {
		fd = resultArg(meta.Args[0], ret, ret.Type().Default())
		shmid, _ = strconv.ParseUint(line.Args[0], 0, 64)
	} else if ret, err := strconv.ParseUint(line.Args[0], 0, 64); err == nil {
		fd = resultArg(meta.Args[0], nil, ret)
		shmid = ret
	} else {
		panic(fmt.Sprintf("error parsing shmat first argument: %s\n", line.Args[0]))
	}

	/*
	 * Parse address.
	 */
	if ret, err := strconv.ParseUint(line.Args[1], 0, 64); err == nil {
		//Fixed shmat position
		addr = ret
		fmt.Printf("Fixed shmat address: %s\n", addr)
	} else if strings.Contains(line.Args[1], "NULL") {
		if ret, err := strconv.ParseUint(line.Result, 0, 64); err == nil {
			addr = ret
			fmt.Printf("Dynamically created shmat addr: %d\n", addr)
		} else {
			panic(err.Error())
		}
	} else {
		//Maybe a -1 in the second argument and strace doesn't parse it as 0xffffffffff
		panic(fmt.Sprintf("Failed to parse shmat addr: %s\n", line.Args[1]))
	}

	for _, flag_field := range strings.Split(line.Args[2], "|") {
		fmt.Printf("Protection: %s\n", flag_field)
		flags |= state.Target.ConstMap[flag_field]
	}

	/*
	Add mapping to tracker
	 */
	call.Args = []Arg{
		fd,
		prog.MakePointerArg(meta.Args[1], addr/pageSize, 0, 1, nil),
		prog.MakeConstArg(meta.Args[2], flags),
	}
	//Cache the mapped address since it is a resource type as well
	call.Ret = prog.MakeReturnArg(meta.Ret)
	return_var = returnType {
		Type: getType(meta.Ret),
		Val: line.Result,
	}
	(*return_vars)[return_var] = call.Ret
	length := uint64(4096)
	if req := state.Tracker.FindShmRequest(shmid);  req != nil {
		length = req.GetSize()
	}
	state.Tracker.CreateMapping(call, len(prog_.Calls), call.Args[1], addr, addr + length)
	return domain.NewSeed(call, state, nil, prog_, len(prog_.Calls), line.Cover)
}

func parseMlock(line *sparser.OutputLine,  prog_ *prog.Prog, state *domain.State, return_vars *map[returnType]Arg) *domain.Seed {

	addr := uint64(0)
	length := uint64(0)
	var dependsOn map[*Call]int = nil


	fmt.Printf("Call: %s\n", line.FuncName)
	for i, _ := range line.Args {
		fmt.Printf("Arg: %d: %v\n", i, line.Args[i])
	}


	meta := state.Target.SyscallMap[line.FuncName]
	call := &prog.Call{
		Meta: meta,
		Ret: returnArg(meta.Ret),
	}
		//We have an anonymous map
	if res, err := strconv.ParseUint(line.Args[0], 0, 64); err == nil {
		addr = res

		fmt.Printf("start: %d\n", addr)
	}

	if res, err := strconv.ParseUint(line.Args[1], 0, 64); err == nil {
		length = res
	} else {
		panic("Failed to parse length argument from mlock\n")
	}

	call.Args = []Arg{
		prog.MakePointerArg(meta.Args[0], addr/pageSize, 0, 1, nil),
		prog.MakeConstArg(meta.Args[1], length),
	}

	if mapping := state.Tracker.FindLatestOverlappingVMA(addr); mapping != nil {
		dependsOn = make(map[*prog.Call]int, 0)
		dependsOn[mapping.GetCall()] = mapping.GetCallIdx()
		for _, dep := range mapping.GetUsedBy() {
			dependsOn[prog_.Calls[dep.Callidx]] = dep.Callidx
		}
		dep := domain.NewMemDependency(len(prog_.Calls), call.Args[0], addr, length)
		mapping.AddDependency(dep)
	}
	return domain.NewSeed(call, state, dependsOn, prog_, len(prog_.Calls), line.Cover)
}

func parseMUnlock(line *sparser.OutputLine,  prog_ *prog.Prog, state *domain.State, return_vars *map[returnType]Arg) *domain.Seed {

	addr := uint64(0)
	length := uint64(0)
	var dependsOn map[*Call]int = nil


	fmt.Printf("Call: %s\n", line.FuncName)
	for i, _ := range line.Args {
		fmt.Printf("Arg: %d: %v\n", i, line.Args[i])
	}


	meta := state.Target.SyscallMap[line.FuncName]
	call := &prog.Call{
		Meta: meta,
		Ret: returnArg(meta.Ret),
	}
	//We have an anonymous map
	if res, err := strconv.ParseUint(line.Args[0], 0, 64); err == nil {
		addr = res

		fmt.Printf("start: %d\n", addr)
	}

	if res, err := strconv.ParseUint(line.Args[1], 0, 64); err == nil {
		length = res
	} else {
		panic("Failed to parse length argument from munlock\n")
	}

	call.Args = []Arg{
		prog.MakePointerArg(meta.Args[0], addr/pageSize, 0, 1, nil),
		prog.MakeConstArg(meta.Args[1], length),
	}

	if mapping := state.Tracker.FindLatestOverlappingVMA(addr); mapping != nil {
		dependsOn = make(map[*prog.Call]int, 0)
		dependsOn[mapping.GetCall()] = mapping.GetCallIdx()
		for _, dep := range mapping.GetUsedBy() {
			dependsOn[prog_.Calls[dep.Callidx]] = dep.Callidx
		}
		dep := domain.NewMemDependency(len(prog_.Calls), call.Args[0], addr, length)
		mapping.AddDependency(dep)
	}
	return domain.NewSeed(call, state, dependsOn, prog_, len(prog_.Calls), line.Cover)
}

func parseMadvise(line *sparser.OutputLine, prog_ *prog.Prog, state *domain.State, return_vars *map[returnType]Arg) *domain.Seed {
	fmt.Printf("Call: %s\n", line.FuncName)
	for i, _ := range line.Args {
		fmt.Printf("Arg: %d: %v\n", i, line.Args[i])
	}
	meta := state.Target.SyscallMap[line.FuncName]
	call := &prog.Call{
		Meta: meta,
		Ret: returnArg(meta.Ret),
	}
	start := uint64(0)
	length := uint64(0)
	advice := uint64(0)
	var dependsOn map[*prog.Call]int = nil


	if res, err := strconv.ParseUint(line.Args[0], 0, 64); err == nil {
		start = res
		fmt.Printf("Start: %d\n", length)
	} else if res, err := strconv.ParseInt(line.Args[0], 0, 64); err == nil{
		if res < 0 {
			start = ^uint64(0)
		}
	}

	if res, err := strconv.ParseUint(line.Args[1], 0, 64); err == nil {
		length = res
	} else if res, err := strconv.ParseInt(line.Args[1], 0, 64); err == nil {
		length = uint64(res)
	}

	if res, err := extractVal(line.Args[2], "mode", &state.Target.ConstMap); err == nil {
		advice = res
	} else {
		panic("Failed to parse the advice of madvise")
	}

	addrArg := prog.MakePointerArg(meta.Args[0], start/pageSize, 0, 1, nil)
	if mapping := state.Tracker.FindLatestOverlappingVMA(start); mapping != nil {
		dependsOn = make(map[*prog.Call]int, 0)
		dependsOn[mapping.GetCall()] = mapping.GetCallIdx()
		for _, dep := range mapping.GetUsedBy() {
			dependsOn[prog_.Calls[dep.Callidx]] = dep.Callidx
		}
		dep := domain.NewMemDependency(len(prog_.Calls), addrArg, start, start+length)
		mapping.AddDependency(dep)

	}

	call.Args = []Arg {
		addrArg,
		prog.MakeConstArg(meta.Args[1], length),
		prog.MakeConstArg(meta.Args[2], advice),
	}


	return domain.NewSeed(call, state, dependsOn, prog_, len(prog_.Calls), line.Cover)
}

func parseInnerCall(val string, typ Type, line *sparser.OutputLine, consts *map[string]uint64,
	return_vars *map[returnType]Arg, s *domain.State) Arg {

	fmt.Println("---------Parsing Inner Call Args-----------")
	fmt.Println(val)

	i := 0
	for val[i] != '(' {
		i++
	}
	call, arg_str := val[:i], val[i:]     // split into form <call>=(<args>)
	arg_str = arg_str[1 : len(arg_str)-1] // strip parentheses

	args := make([]string, 0)

	for len(arg_str) > 0 {
		param, rem := ident(arg_str)
		arg_str = rem
		args = append(args, param)
	}
	fmt.Printf("call %v\n", call)
	fmt.Printf("args: %v\n", args)

	fmt.Println(reflect.TypeOf(typ))
	fmt.Println(typ)

	switch a := typ.(type) {
	/* just choose max allowed for proc args */
	case *ProcType:
		return constArg(a, uint64(a.ValuesPerProc-1))
	case *UnionType:
		fmt.Println("PARSING UNION TYPE")
		/* I know this is horrible but there's no other way to know the union type! :( */
		if strings.Contains(line.FuncName, "$inet6") && call == "htonl" {
			var inner_arg Arg
			var optType Type
			if i, err := strconv.ParseUint(args[0], 0, 32); err == nil {
				if Htonl(uint32(i)) == 0 {
					optType = a.Fields[0]
				}
			}
			switch t := optType.(type) {
			case *StructType:
				fmt.Printf("PARSING STRUCT TYPE\n")
				struct_args := make([]Arg, 0)
				for _, field := range t.Fields {
					var inner_arg Arg
					switch ft := field.(type) {
					case *ArrayType:
						fmt.Print("PARSING ARRAY TYPE\n")
						switch t := ft.Type.(type) {
						case *IntType:
							fmt.Print("PARSING INT TYPE\n")
							if i, err := strconv.ParseUint(args[0], 0, 32); err == nil {
								inner_arg = groupArg(field, []Arg{constArg(ft.Type, uint64(Htonl(uint32(i))))})

							} else {
								failf("failed to parse inner call %v\n", val)
							}
						case *ConstType:
							fmt.Print("PARSING CONST TYPE\n")
							if i, err := strconv.ParseUint(args[0], 0, 32); err == nil {
								inner_arg = groupArg(field, []Arg{constArg(ft.Type, uint64(Htonl(uint32(i))))})

							} else {
								failf("failed to parse inner call %v\n", val)
							}
						default:
							fmt.Printf("FIELD NAME: %s\n", t.Name())
						}

					}
					struct_args = append(struct_args, inner_arg)
				}
				return unionArg(a, groupArg(t, struct_args), optType)
			case *UnionType:
				fmt.Print("YEAH UNION TYPE\n")
			}
			if i, err := strconv.ParseUint(args[0], 0, 32); err == nil {
				fmt.Printf("HTONL parsed: %d\n", Htonl(uint32(i)))
				inner_arg = constArg(typ, uint64(Htonl(uint32(i))))
			} else {
				failf("failed to parse inner call %v\n", val)
			}
			return unionArg(a, inner_arg, optType)
		}
		if call == "inet_addr" {
			fmt.Printf("UNION TYPE inet inet_addr parsing\n")
			var optType Type
			var inner_arg Arg
			args[0] = args[0][1 : len(args[0])-1] // strip quotes
			if args[0] == "0.0.0.0" {
				optType = a.Fields[0]
				inner_arg = constArg(optType, uint64(0x00000000))
			} else if args[0] == "127.0.0.1" {
				fmt.Printf("HERHEHREHRHE\n")
				optType = a.Fields[3]
				inner_arg = constArg(optType, uint64(0x7f000001))
			} else if args[0] == "255.255.255.255" {
				optType = a.Fields[6]
				inner_arg = constArg(optType, uint64(0xffffffff))
			} else {
				fmt.Printf("unsupported inet_addr %v in %v\n", args[0], val)
				// TODO: is this right? Will syzkaller mutate later on? How do we hit these EADDRNOTAVAIL blocks
				optType = a.Fields[7]
				inner_arg = constArg(optType, uint64(0x10000000))
			}
			return unionArg(a, inner_arg, optType)
		} else if strings.Contains(line.FuncName, "$inet6") && call == "inet_pton" {
			var optType Type
			var inner_arg Arg
			inner_arg, optType = parseIpV6(a, args[1])
			if optType == nil {
				failf("NIL OPT TYPE WHILE PARSING\n")
			}
			/*

				if args[1] == "\"::1\"" {
					optType = a.Options[3]
				} else if args[1] == "\"::\"" {
					optType = a.Options[0]
				} else {
					failf("invalid sin_addr `%v` in call to inet_pton: %v\n for call%v \n", args[1], val, line.Unparse())
				}
				switch b := optType.(type) {
				case *sys.StructType:
					a0 := b.Fields[0].(*sys.ConstType)
					a1 := b.Fields[1].(*sys.ConstType)
					a0_arg := constArg(a0, a0.Val)
					a1_arg := constArg(a1, a1.Val)
					inner_arg = groupArg(b, []Arg{a0_arg, a1_arg})
				default:
					failf("inner option not a structType %v\n", line.Unparse())
				}
			*/
			return unionArg(a, inner_arg, optType)
		} else {
			fmt.Printf("`%v`\n", args[0])
			failf("unexpected uniontype call %v parsing arg %v\n", line.Unparse(), val)
		}
	default:
	}

	var arg Arg
	switch call {
	case "htons":
		if i, err := strconv.ParseUint(args[0], 0, 16); err == nil {
			arg = constArg(typ, uint64(Htons(uint16(i))))
		} else {
			if v, ok := val_from_const(args[0], consts); ok {
				arg = constArg(typ, uint64(Htons(uint16(v))))
			} else {
				failf("failed to parse inner call %v\n", val)
			}
		}
	case "htonl":
		if i, err := strconv.ParseUint(args[0], 0, 32); err == nil {
			arg = constArg(typ, uint64(Htonl(uint32(i))))
		} else {
			if v, ok := val_from_const(args[0], consts); ok {
				arg = constArg(typ, uint64(Htonl(uint32(v))))
			} else {
				failf("failed to parse inner call %v\n", val)
			}
		}
	case "inet_addr":
		args[0] = args[0][1 : len(args[0])-1] // strip quotes
		if args[0] == "0.0.0.0" {
			arg = constArg(typ, uint64(0x00000000))
		} else if args[0] == "127.0.0.1" {
			arg = constArg(typ, uint64(0x7f000001))
		} else if args[0] == "255.255.255.255" {
			arg = constArg(typ, uint64(0xffffffff))
		} else {
			arg = constArg(typ, uint64(0x7f000001))
			// failf("unsupported inet_addr %v in %v\n", args[0], val)
		}
	case "makedev":
		parsedDevice := MakeDev(val)
		val, _ := strconv.ParseUint(parsedDevice, 10, 64)
		arg = constArg(typ, val)
	case "inet_pton":
		fmt.Printf("ARGS: %s\n", args[1])
		fmt.Printf("PARSED IP: %v\n", net.ParseIP(args[1][1:len(args[1])-1]))
		fmt.Printf("TYP: %v\n", typ.Name())
		if args[1] == "\"::1\"" {
			arg = constArg(typ, uint64(0x7f000001))
		} else if args[1] == "\"::\"" {
			arg = constArg(typ, uint64(0xffffffff))
		} else {
			failf("invalid sin_addr `%v` in call to inet_pton: %v\n for call%v \n", args[1], val, line.Unparse())
		}
	default:
		failf("unrecognized inner call %v\n", val)
	}

	return arg
	/*
		if _, ok := Unsupported[call]; ok {
			failf("Inner call unsupported %v\n", val)
		}

		meta := sys.CallMap[call]
		if meta == nil {
			failf("Inner call unknown %v\n", val)
		}

		c := &Call{
			Meta: meta,
			Ret:  returnArg(meta.Ret),
		}

		var calls []*Call
		i = 0

		for len(arg_str) > 0 {
			param, rem := ident(arg_str)
			arg_str = rem
			inner_arg, inner_calls := parseArg(meta.Args[i], param, consts, return_vars, call, s)
			c.Args = append(c.Args, inner_arg)
			calls = append(calls, inner_calls...)
			i++
		}
		if i != len(meta.Args) {
			failf("did not parse sufficient arguments for inner call %v\n", val)
		}
		calls = append(calls, c)
		fmt.Println("\n---------Done Parsing Inner Call--------\n")

		return calls
	*/
}

func cache(return_vars *map[returnType]Arg, return_var returnType, arg Arg, returned bool) bool {
	/* TODO: may want to have more fine-grained type for caching to reduce collisions.
	as of now we over-write any collision, but this may not be optimal behavior.
	*/
	if arg == nil {
		return false
	}
	switch arg.(type) {
	case *ResultArg, *ReturnArg:
		if returned {
			fmt.Printf("caching %v %v\n", return_var, arg.Type().Name())
			(*return_vars)[return_var] = arg
			return true
		}
		if _, ok := (*return_vars)[return_var]; !ok {
			fmt.Printf("caching %v %v\n", return_var, arg.Type().Name())
			(*return_vars)[return_var] = arg
			return true
		}
		return false
	default:
		return false
	}
}

func process(target *Target, line *sparser.OutputLine, consts *map[string]uint64, return_vars *map[returnType]Arg) bool{
	defer func() { EnabledSyscalls[line.FuncName] = true }()
	skip := false
	switch line.FuncName {
	case "accept", "accept4":
		return_var := returnType{
			"ResourceType" + "fd",
			line.Args[0],
		}
		if arg, ok := (*return_vars)[return_var]; ok {
			switch a := arg.Type().(type) {
			case *ResourceType:
				if label, ok := Accept_labels[a.TypeName]; ok {
					line.FuncName = line.FuncName + label
					fmt.Printf("discovered accept type: %v\n", line.FuncName)
				} else {
					failf("unknown accept variant for type %v\nline: %v\n", a.TypeName, line.Unparse())
				}
			default:
				failf("return_var for accept is NOT a resource type %v\n", line.Unparse())
			}
		}
		return false
	case "bpf":
		line.FuncName = line.FuncName + Bpf_labels[line.Args[0]]
	case "bind", "connect":
		var m *map[string]string
		label := ""
		return_var := returnType{
			"ResourceType" + "fd",
			line.Args[0],
		}
		if line.FuncName == "bind" {
			m = &Bind_labels
		} else {
			m = &Connect_labels
		}
		if arg, ok := (*return_vars)[return_var]; ok {
			switch a := arg.Type().(type) {
			case *ResourceType:
				if label, ok = (*m)[a.TypeName]; ok {
					line.FuncName = line.FuncName + label
					if label == "" { /* we don't know what variant, set uniontype to nil */
						line.Args[1] = "nil"
					}
					fmt.Printf("discovered type: %v\n", line.FuncName)
				} else {
					failf("unknown variant for type %v\nline: %v\n", a.TypeName, line.Unparse())
				}
			default:
				failf("first arg is NOT a resource type %v\n", line.Unparse())

			}
		} else {

			fmt.Printf("Could not find file descriptor for function: %s. Looking at second arg\n", line.FuncName)
			if len(line.Args) > 1 {
				if strings.Contains(line.Args[1], "AF_INET") {
					line.FuncName = line.FuncName + (*m)["AF_INET"]
					label = "$inet"
				}
			}
		}

		if label == "$inet" || label == "$inet6" {
			line.Args[1] = strings.Replace(line.Args[1], "}", ", pad=nil}", 1)
		}
	case "epoll_ctl":
		line.FuncName = line.FuncName + "$" + line.Args[1]
	case "socket":
		if label, ok := Socket_labels[line.Args[0]]; ok {
			line.FuncName += label
		} else {
			failf("unrecognized socket variant %v\n", line.Unparse())
		}
	case "getsockopt":
		fmt.Println(line.Unparse())
		fmt.Printf("arg 1 and 2: %v and %v\n", line.Args[1], line.Args[2])
		if name, ok := SocketLevel_map[line.Args[1]]; ok { /*strace uses SOL levels */
			line.Args[1] = name
		}
		variant := Pair{line.Args[1], line.Args[2]}
		/* key collision, need to resolve manually */
		if line.Args[1] == "SOL_SOCKET" && line.Args[2] == "SO_PEERCRED" {
			if line.Args[3][0] == '"' {
				line.FuncName += "$sock_buf"
			} else {
				line.FuncName += "$sock_cred"
			}
			return skip
		}

		if label, ok := Getsockopt_labels[variant]; ok {
			line.FuncName += label
		} else if _, ok := val_from_const(variant.B, consts); ok {
			line.FuncName += ("$" + variant.B)
		}
		//If it isn't a special variant then we treat it like a good old socket
	case "getsockname":
		var label string
		return_var := returnType{
			"ResourceType" + "fd",
			line.Args[0],
		}
		if arg, ok := (*return_vars)[return_var]; ok {
			switch a := arg.Type().(type) {
			case *ResourceType:
				if label, ok = Getsockname_labels[a.TypeName]; ok {
					line.FuncName = line.FuncName + label
					fmt.Printf("discovered type: %v\n", line.FuncName)
				} else {
					failf("unknown variant for type %v\nline: %v\n", a.TypeName, line.Unparse())
				}
			default:
				failf("return_var for getsockname is NOT a resource type %v\n", line.Unparse())
			}
		}
	case "select":
		var f = func(arg string) string {
			ret := "{"
			if arg == "NULL" {
				return "nil"
			}
			arg = arg[1 : len(arg)-1]
			masks := strings.Split(arg, " ")
			for len(masks) < 8 {
				masks = append(masks, "nil")
			}
			for i, mask := range masks {
				if i == len(masks)-1 {
					ret += mask
				} else {
					ret += mask + ", "
				}
			}
			ret += "}"
			return ret
		}
		for i := 1; i <= 3; i++ {
			line.Args[i] = f(line.Args[i])
		}
		fmt.Printf("Processed select: %v\n", line.Unparse())
	case "setsockopt":
		fmt.Printf("setsockopt argv1: %s\n", line.Args[1])
		line.Args[1] = SocketLevel_map[line.Args[1]]
		variant := Pair{line.Args[1], line.Args[2]}

		fmt.Printf("variant: %v\n", variant)
		if label, ok := Setsockopt_labels[variant]; ok {
			line.FuncName += label
		} else if _, ok := val_from_const(variant.B, consts); ok {
			line.FuncName += ("$" + variant.B)
		} else {
			fmt.Printf("unrecognized set sockopt variant %v\n", line.Unparse())
		}
	case "sendto":
		var label string
		return_var := returnType{
			"ResourceType" + "fd",
			line.Args[0],
		}
		if arg, ok := (*return_vars)[return_var]; ok {
			switch a := arg.Type().(type) {
			case *ResourceType:
				if label, ok = Sendto_labels[a.TypeName]; ok {
					line.FuncName = line.FuncName + label
					fmt.Printf("discovered sendto type: %v\n", line.FuncName)
				} else {
					failf("unknown sendto variant for type %v\nline: %v\n", a.TypeName, line.Unparse())
				}
			default:
				failf("return_var for accept is NOT a resource type %v\n", line.Unparse())
			}
		}

		if label == "$inet" || label == "$inet6" {
			line.Args[4] = strings.Replace(line.Args[4], "}", ", pad=nil}", 1)
		}
	case "sendmsg":
		return_var := returnType{
			"ResourceType" + "fd",
			line.Args[0],
		}
		if arg, ok := (*return_vars)[return_var]; ok {
			switch a := arg.Type().(type) {
			case *ResourceType:
				fmt.Printf("Sendmsg typeName: %s\n", a.TypeName)
				if label, ok := Sendmsg_labels[a.TypeName]; ok {
					line.FuncName = line.FuncName + label
					fmt.Printf("discovered type: %v\n", line.FuncName)
				} else {
					failf("unknown variant for type %v\nline: %v\n", a.TypeName, line.Unparse())
				}
			default:
				failf("return_var is NOT a resource type %v\n", line.Unparse())
			}
		}
	case "recvfrom":
		return_var := returnType{
			"ResourceType" + "fd",
			line.Args[0],
		}
		if arg, ok := (*return_vars)[return_var]; ok {
			switch a := arg.Type().(type) {
			case *ResourceType:
				if label, ok := Recvfrom_labels[a.TypeName]; ok {
					line.FuncName = line.FuncName + label
					if label == "$inet" || label == "$inet6" {
						line.Args[4] = strings.Replace(line.Args[4], "}", ", pad=nil}", 1)
					}
					fmt.Printf("discovered type: %v\n", line.FuncName)
				} else {
					failf("unknown variant for type %v\nline: %v\n", a.TypeName, line.Unparse())
				}
			default:
				failf("return_var is NOT a resource type %v\n", line.Unparse())
			}
		} else {
			skip = true
		}
	case "fcntl":
		if label, ok := Fcntl_labels[line.Args[1]]; ok {
			line.FuncName += label
			if meta, ok := target.SyscallMap[line.FuncName]; ok {
				if len(line.Args) < len(meta.Args) { /* third arg is missing, put in default */
					line.Args = append(line.Args, strconv.FormatUint(uint64(meta.Args[2].Default()), 10))
				}
			} else {
				failf("call not found: %v\n", line.FuncName)
			}
		} else {
			fmt.Printf("unrecognized fcntl variant %v\n", line.Unparse())
		}
	case "sched_setaffinity":
		s := line.Args[2]
		if s[0] == '[' && s[len(s)-1] == ']' {
			line.Args[2] = s[1 : len(s)-1]
		}
	case "capget":
		line.Args[1] = "[]"
	case "rt_sigaction":
		if len(line.Args) < 5 {
			line.Args = append(line.Args, "{fake=0}")
		}
		if strings.Contains(line.Args[0], "SIGRT_") {
			min := int((*consts)["SIGRTMIN"])
			max := int((*consts)["SIGRTMAX"])
			line.Args[0] = strconv.Itoa(rand.Intn(max-min+1) + min)
		}
		if strings.Contains(line.Args[1], "~[RTMIN RT_1]") {
			line.Args[1] = strings.Replace(line.Args[1], "~[RTMIN RT_1]", "[SIGRTMIN]", 1)
		} else if strings.Contains(line.Args[1], "[RT_3]") {
			line.Args[1] = strings.Replace(line.Args[1], "[RT_3]", "[]", 1)
		} else if !strings.Contains(line.Args[1], "sa_mask=[]") {
			/* append 'SIG' to mask label */
			line.Args[1] = strings.Replace(line.Args[1], "sa_mask=[", "sa_mask=[SIG", 1)
		}
	case "rt_sigprocmask": // TODO: look at ltp_rtsigprocmask02. how to properly handle the addr args?
		// TODO: removed '~' from second arg orgiinally ~[RTMIN RT_1]
		if strings.Contains(line.Args[1], "RTMIN") || strings.Contains(line.Args[1], "RT_3") || strings.Contains(line.Args[1],"RT_1") {
			line.Args[1] = "{mask=0x8001}"
		} else if strings.Contains(line.Args[1], "RTMAX") {
			line.Args[1] = "{mask=0xfffffffffffffffe}"
		} else if line.Args[1] == "NULL" {
			line.Args[1] = "[]"
		}

		if strings.Contains(line.Args[2], "[RT_3]") { // todo: can't find value of rt_3
			new := strings.Replace(line.Args[1], "[RT_3]", "[]", 1)
			line.Args[1] = new
		}
	case "ioctl":
		candidateName := line.FuncName + "$" + line.Args[1]
		if _, ok := target.SyscallMap[candidateName]; !ok {
			if _, ok = Ioctl_map[line.Args[1]]; ok {
				line.FuncName = line.FuncName + "$" + Ioctl_map[line.Args[1]]
			}
		} else {
			line.FuncName = line.FuncName + "$" + line.Args[1]
		}
	case "open":
		if len(line.Args) == 2 {
			line.Args = append(line.Args, "0")
		}

	case "mknod":
		if len(line.Args) == 2 {
			line.Args = append(line.Args, "0")
		}
	case "shmctl":
		candidateName := line.FuncName + "$" + line.Args[1]
		if _, ok := target.SyscallMap[candidateName]; !ok {
			fmt.Printf("unknown shmctl variant %v\n", line.Unparse())
		} else {
			line.FuncName = candidateName
		}
	case "keyctl":
		if label, ok := Keyctl_labels[line.Args[0]]; ok {
			line.FuncName = line.FuncName + label
		} else {
			fmt.Printf("unknown keyctl variant %v\n", line.Unparse())
		}
	case "prctl":
		if label, ok := Prctl_labels[line.Args[0]]; ok {
			line.FuncName = line.FuncName + label
		} /*else {
			failf("unknown prctl variant %v\n", line.Unparse())
		}*/
	default:
	}
	return skip
}

func val_from_const(constant string, consts *map[string]uint64) (uint64, bool) {
	if v, ok := (*consts)[constant]; ok {
		return v, true
	} else if v, ok := Special_Consts[constant]; ok {
		return v, true
	}
	return 0, false
}

func parseArg(typ Type, strace_arg string,
	consts *map[string]uint64, return_vars *map[returnType]Arg,
	line *sparser.OutputLine, s *domain.State) (arg Arg, calls []*Call, err error) {
	call := line.FuncName
	fmt.Printf("-----Entering parseArg-------"+
		"\nparsing arg: %v"+
		"\nfor call: %v \n", strace_arg, call)
	// check if this is a return arg
	if arg := isReturned(typ, strace_arg, return_vars); arg != nil {
		fmt.Println("Discovered return type!")
		fmt.Println("\n-------exiting parseArg--------\n")
		return arg, nil, nil
	}

	switch a := typ.(type) {
	case *FlagsType:
		fmt.Printf("Call: %v\nparsing FlagsType %v\n", call, strace_arg)
		if strace_arg == "nil" || strace_arg == "NULL" {
			return constArg(a, a.Default()), nil, nil
		}
		if strings.Contains(strace_arg, "\"") {
			if strings.Contains(strace_arg, "0x") {
				//Some setsockopt calls like SOL_RAW have 0x7
				if val, err := strconv.ParseUint(strace_arg[1:len(strace_arg)-1], 16, 64); err == nil {
					arg, calls = constArg(a, val), nil
				} else {
					panic(err.Error())
				}
			} else if val, err := strconv.ParseUint(strace_arg[1:len(strace_arg)-1], 10, 64); err == nil {
				arg, calls = constArg(a, val), nil
			}
		} else {
			if val, err := extractVal(strace_arg, a.FldName, consts); err == nil {
				fmt.Printf("2: Flags type parsing value: %v\n", val)
				arg, calls = constArg(a, uint64(val)), nil
			} else if val, err := uintToVal(strace_arg); err == nil {
				fmt.Printf("1: Flags type parsing value: %v\n", val)
				arg, calls = constArg(a, uint64(val)), nil
			} else {
				fmt.Printf("3: Flags type parsing value: %v\n", a.Default())
				arg, calls = constArg(a, a.Default()), nil
			}
		}

	case *ResourceType:
		fmt.Printf("Resource Type: %v\n", a.Desc)
		// TODO: special parsing required if struct is type timespec or timeval
		if strace_arg == "nil" || a.Dir() == DirOut {
			return resultArg(a, nil, a.Default()), nil, nil
		}
		if v, ok := val_from_const(strace_arg, consts); ok {
			return resultArg(a, nil, uint64(v)), nil, nil
		}
		strace_arg = strings.TrimSpace(strace_arg)
		//Need to parse as int because we may have negative file descriptor
		extracted_int, err := strconv.ParseInt(strace_arg, 0, 64)
		if err != nil {
			fmt.Fprintf(os.Stdout, "Error parsing resource arg %s for call %s, desc: %s\n", strace_arg, call, err.Error())
			arg, calls = resultArg(a, nil, a.Default()), nil
		} else {
			arg, calls = resultArg(a, nil, uint64(extracted_int)), nil
			err = nil
		}
		// TODO: special values onlystate.Target.ConstMap[prot_field]
	case *BufferType:
		fmt.Printf("Parsing Buffer Type: %v\n", strace_arg)

		if a.Dir() != DirOut && strace_arg != "nil" {
			var buffer []byte
			strippedString, newLen := utils.StripString(strace_arg)
			decodedString := utils.ParseString(strippedString)
			switch a.Kind {
			case BufferFilename, BufferString:
				fmt.Printf("BUFFER BLOB STRING\n")
				buffer = make([]byte, newLen+1)
				buffer[len(decodedString)] = '\x00'
			case BufferBlobRand:
				fmt.Printf("BUFFER BLOB RAND\n")
				buffer = make([]byte, newLen)
			case BufferBlobRange:
				fmt.Printf("BUFFER BLOB RANGE\n")
				size := rand.Intn(int(a.RangeEnd)-int(a.RangeBegin)+1) + int(a.RangeBegin)
				fmt.Printf("SIZE: %d\n", size)
				buffer = make([]byte, size)
			default:
				failf("unexpected buffer type. call %v arg %v", call, strace_arg)
			}
			fmt.Printf("Strace Arg Len: %d\n", len(strace_arg))
			fmt.Printf("Stripped String: %s\n", strippedString)
			strace_arg_arr := []byte(decodedString)
			for i := 0; i < len(buffer); i++ {
				if i < len(strace_arg_arr) {
					buffer[i] = strace_arg_arr[i]
				}
			}
			arg = dataArg(a, buffer)
		} else {
			if strace_arg != "nil" && strace_arg[0] == '"' { /* make buffer size of given string */
				_, newLen := utils.StripString(strace_arg)
				return dataArg(a, make([]byte, newLen)), nil, nil
			}
			switch a.Kind {
			case BufferFilename, BufferString:
				arg = dataArg(a, make([]byte, len(strace_arg)-1)) // -2 for the " "
			case BufferBlobRand:
				size := rand.Intn(256)
				arg = dataArg(a, make([]byte, size))
			case BufferBlobRange:
				size := rand.Intn(int(a.RangeEnd)-int(a.RangeBegin)+1) + int(a.RangeBegin)
				fmt.Printf("HERE IS THE SIZE NIGGA: %d\n", size)
				arg = dataArg(a, make([]byte, size))
			default:
				failf("unexpected buffer type. call %v arg %v", call, strace_arg)
			}
		}
		fmt.Printf("parsed buffer type with val: %v\n", arg.(*DataArg).Data)
		return arg, nil, nil
	case *PtrType:
		fmt.Printf("Call: %s \n Pointer with inner type: %v\n", call, a.Type.Name())
		if strace_arg == "NULL" {
			fmt.Printf("Generating DEFAULT?\n")
			return DefaultArg(typ), nil, nil
		}
		if strace_arg == "NULL" && a.IsOptional {
			fmt.Printf("ARG is NULL and is optional\n")
			var size uint64 = 0
			switch b := a.Type.(type) {
			case *BufferType:
				if !b.Varlen() {
					size = b.Size()
				}
			case *StructType:

			default:
				size = a.Type.Size()
			}
			arg, calls, err = addr(s, a, size, nil)
			if err != nil {
				fmt.Printf("ERROR IS NOT NILL ARG NULL AND IS OPTIONAL")
				return
			}
			return arg, calls, nil
		}

		if strace_arg == "NULL" && !a.IsOptional {
			strace_arg = "nil" // just render the default value
		}

		ptr := parsePointerArg(strace_arg)
		if ptr.Val == "" {
			//Most likely our trace is testing for bad addresses
			//we just return empty pointer

			ptr.Val = "nil" //TODO: this is really bad, consider refactoring parseArg
			fmt.Printf("PTR VAL is empty\n")
			//return pointerArg(a.Type, 0xffffffff >> pageSize, pageSize-1, 1,  nil), nil, nil
		}

		if ptr.Val[0] == '[' {
			switch a.Type.(type) {
			case *IntType, *LenType, *CsumType, *ResourceType:
				ptr.Val = ptr.Val[1 : len(ptr.Val)-1]
			default:
			}
		}

		inner_arg, inner_calls, err_ := parseArg(a.Type, ptr.Val, consts, return_vars, line, s)
		if err_ != nil {
			fmt.Fprint(os.Stderr, "Error parsing arg: %s\n", err_.Error())
			err = err_
			return
		}

		/* cache this pointer value */
		switch a.Type.(type) {
		/* don't cache for these types */
		case *PtrType, *ArrayType, *StructType, *BufferType, *UnionType:
		default:
			return_var := returnType{
				getType(a.Type),
				ptr.Val,
			}
			fmt.Printf("caching %v result for %v %v\n", return_var, call, a.Type.Name())
			fmt.Printf("caching %v result for %v %v\n", return_var, call, a.Type.Name())
			cache(return_vars, return_var, inner_arg, false)
		}

		outer_arg, outer_calls, err := addr(s, a, inner_arg.Size(), inner_arg)
		if err != nil {
			return nil, nil, err
		}
		inner_calls = append(inner_calls, outer_calls...)
		arg, calls = outer_arg, inner_calls
	case *IntType:
		var extracted_int uint64
		err = nil
		if strace_arg == "nil" || a.Dir() == DirOut || strace_arg == "NULL" {
			extracted_int = uint64(a.Default())
		} else {
			strace_arg = func() string {
				for _, macro := range Macros {
					if strings.Contains(strace_arg, macro) {
						return MacroExpand_map[macro](strace_arg)
					}
				}
				return strace_arg
			}()

			if strace_arg[0] == '[' && strace_arg[len(strace_arg)-1] == ']' {
				strace_arg = strace_arg[1 : len(strace_arg)-1]
			}
			extracted_int, err = uintToVal(strace_arg)
		}
		if err != nil { /* const */
			extracted_int, err = extractVal(strace_arg, a.FldName, consts)
		}
		if err != nil {
			fmt.Errorf("cannot parse IntType input %v and interpreting it as 0\n", strace_arg).Error()
		}
		fmt.Printf("Parsed IntType %v with val %v\n", strace_arg, int(extracted_int))
		arg, calls = constArg(a, uint64(extracted_int)), nil
	case *VmaType:
		//panic("VMA Type encountered")
		err = nil
		fmt.Printf("VMA Type: %v Call: %s\n", strace_arg, call)
		npages := uint64(1)
		// TODO: strace doesn't give complete info, need to guess random page range
		if a.RangeBegin != 0 || a.RangeEnd != 0 {
			npages = uint64(int(a.RangeEnd)) // + r.Intn(int(a.RangeEnd-a.RangeBegin+1)))
		}
		var arg Arg
		arg = pointerArg(typ, 0, 0, npages, nil)
		s.Tracker.AddAllocation(s.CurrentCall, pageSize, arg)
		//We might encounter an mlock done because of a brk
		//But strace doesn't support brk so we need to allocate the address
		/*
		for i := uint64(0); i < maxPages-npages; i++ {
			free := true
			for j := uint64(0); j < npages; j++ {
				if s.Pages[i+j] {
					free = false
					break
				}
			}
			if !free {
				continue
			}

			for j := uint64(0); j < npages; j++ {
				s.Pages[i+j] = true
			}
			// found a free memory section, let's mmap
			c := createMmapCall(i, npages)
			arg, calls := pointerArg(typ, i, 0, npages, nil), []*Call{c}
			//if a.Dir() == sys.DirOut {
			//	arg.Val = a.Default()
			//}
			return arg, calls, err
		}*/
		return arg, nil, nil
		failf("out of memory\n")
	case *ConstType:
		fmt.Printf("Parsing Const type %v with type: %s\n", strace_arg, a.Name())
		if a.Dir() == DirOut {
			return constArg(a, a.Default()), nil, nil
		}
		data, e := uintToVal(strace_arg)
		if e != nil {
			data, e = extractVal(strace_arg, a.FldName, consts)
		}
		if strace_arg == "nil" || e != nil {
			fmt.Printf("Creating constarg with val %v\n", a.Val)
			return constArg(a, a.Val), nil, nil
		}
		fmt.Printf("Creating constarg with val %v\n", data)
		return constArg(a, data), nil, nil
	case *ProcType:
		fmt.Println("Proc Type", strace_arg)
		var data uint64
		var e error
		if a.Dir() == DirOut {
			data = uint64(a.Default())
		} else {
			data, e = uintToVal(strace_arg)
		}
		if e == nil {
			if data > a.ValuesPerProc-1 {
				data = a.ValuesPerProc - 1
			}
		} else {
			data = a.ValuesPerProc - 1
		}
		fmt.Printf("Proc Type parsing proc value %v\n", data)
		return constArg(a, uint64(data)), nil, nil
	case *LenType, *CsumType:
		fmt.Println("Len/Csum Type")
		var data uint64
		var e error
		if strace_arg == "nil" || strace_arg == "NULL" {
			data = 0
		} else {
			data, e = uintToVal(strace_arg)
		}
		if e == nil {
			return constArg(a, uint64(data)), nil, nil
		}
		return constArg(a, 0), nil, nil
	case *ArrayType:
		var args []Arg
		if strace_arg == "nil" || strace_arg == "" {
			fmt.Printf("Filling out default values for nil array\n")
			if a.Kind == ArrayRangeLen {
				fmt.Printf("Kid of arg is array range len with type: %s\n", a.Type.Name())
				size := rand.Intn(int(a.RangeEnd)-int(a.RangeBegin)+1) + int(a.RangeBegin)
				for i := 0; i < size; i++ {
					inner_arg, inner_calls, err_ := parseArg(a.Type, "nil", consts, return_vars, line, s)
					if err_ != nil {
						err = err_
						return
					}
					args = append(args, inner_arg)
					calls = append(calls, inner_calls...)
				}

			}
			fmt.Printf("args: %v\n", args)
			return groupArg(typ, args), nil, nil
		}
		// clip the square brackets
		if strace_arg[0] == '[' && strace_arg[len(strace_arg)-1] == ']' {
			strace_arg = strace_arg[1 : len(strace_arg)-1]
		}
		fmt.Printf("ArrayType %v\n", a.TypeName)

		for len(strace_arg) > 0 {
			param, rem := ident(strace_arg)
			strace_arg = rem
			inner_arg, inner_calls, err_ := parseArg(a.Type, param, consts, return_vars, line, s)
			if err_ != nil {
				err = err_
				return
			}
			args = append(args, inner_arg)
			calls = append(calls, inner_calls...)
		}
		arg = groupArg(typ, args)
	case *StructType:
		fmt.Printf("Strace arg pre process: %s\n", strace_arg)
		preProcessStructs(typ, &strace_arg)
		fmt.Printf("Strace arg post process: %s\n", strace_arg)
		arg, calls, err = parseStructs(typ, strace_arg, consts, return_vars, line, s)
		return
	case *UnionType:
		fmt.Printf("Parsing unionType for: %v with type: %s\n", strace_arg, a.TypeName)
		unionIdx := identifyUnionType(typ, strace_arg, consts, return_vars, line)
		optType := a.Fields[unionIdx]
		opt, inner_calls, err_ := parseArg(optType, strace_arg, consts, return_vars, line, s)
		if err_ != nil {
			err = err_
			return
		}
		calls = append(calls, inner_calls...)
		arg = unionArg(a, opt, optType)
	default:
		fmt.Printf("Call: %s\n Arg: %v\n", call, typ)
		fmt.Printf("Args: %v\n", reflect.TypeOf(typ))
		panic("uncaught type")
	}

	fmt.Println("-------exiting parseArg--------")

	return arg, calls, nil
}

func identifyUnionType(typ Type, strace_arg string,
			consts *map[string]uint64,
			return_vars *map[returnType]Arg,
			line *sparser.OutputLine) int {

	switch line.FuncName {
	case "sendmsg":
		return sendMsgUnion(typ, strace_arg, consts, return_vars, line)
	default:
		return 0;
	}
}

func sendMsgUnion(typ Type, strace_arg string,
			consts *map[string]uint64,
			return_vars *map[returnType]Arg,
			line *sparser.OutputLine) int {
	var sendMsgType string
	return_var := returnType{
		"ResourceType" + "fd",
		line.Args[0],
	}
	if arg, ok := (*return_vars)[return_var]; ok {
		switch a := arg.Type().(type) {
		case *ResourceType:
			sendMsgType = a.TypeName
		default:
			failf("return_var is NOT a resource type %v\n", line.Unparse())
		}
	}
	fmt.Printf("send msg type: %s\n", sendMsgType)
	if sendMsgType == "" {
		if strings.Contains(strace_arg, "AF_INET") {
			return 1
		}
	}
	switch sendMsgType {
	case "sock_in":
		return 1
	case "sock_unix":
		return 0
	case "sock_netlink":
		return 5
	case "sock_in6":
		return 4
	default:
		return 0
	}
}

func ident(arg string) (string, string) {
	fmt.Printf("ident arg: %s\n", arg)
	s := make(Stack, 0)
	var r byte
	for i := 0; i < len(arg); i++ {
		// skip whitespace and commas
		for i < len(arg) && (arg[i] == ' ' || arg[i] == '\t' || arg[i] == ',') {
			i++
		}

		j := i

		var inquote bool = false
		var sawSpecialChar bool = false
		for ; i != len(arg) || len(s) != 0; i++ {
			if !inquote && !sawSpecialChar {
				if arg[i] == '"' {
					inquote = true
					continue
				}
				if arg[i] == '\\' {
					fmt.Printf("i: %d\n", i)
					fmt.Printf("Saw special char here\n")
					sawSpecialChar = true
					continue
				}
				if len(s) == 0 && arg[i] == ',' {
					fmt.Printf("i: %d\n", i)
					fmt.Printf("saw comma breaking\n")
					break
				}
				if arg[i] == '[' || arg[i] == '{' || arg[i] == '(' {
					fmt.Printf("i: %d\n", i)
					fmt.Printf("pushing character\n")
					s = s.Push(arg[i])
					continue
				}
				if arg[i] == ']' {
					s, r = s.Pop()
					if r != '[' {

					}
					continue
				}
				if arg[i] == '}' {
					s, r = s.Pop()
					if r != '{' {
						failf("illegal argument format %v\n", arg)
					}
					continue
				}
				if arg[i] == ')' {
					fmt.Printf("i: %d\n", i)
					fmt.Printf("popping character\n")
					s, r = s.Pop()
					if r != '(' {
						failf("illegal argument format %v\n", arg)
					}
					continue
				}
			} else {
				fmt.Printf("i: %d, %s\n", i, string(arg[i]))
				if arg[i] == '\\' {
					sawSpecialChar = true
				}
				if arg[i] == '"' {
					if sawSpecialChar {
						//We have a nested string we can continue
						fmt.Printf("Saw special char set to false\n")
						sawSpecialChar = false
						continue
					}
					inquote = false
				} else if sawSpecialChar && arg[i] != '\\' {
					sawSpecialChar = false
				}
			}

		}
		return arg[j:i], arg[i:]
	}
	fmt.Printf("Error, invalid arg. Paranthesis do not match: %v\n", arg)
	panic("ident failed")
}

func isReturned(typ Type, strace_arg string, return_vars *map[returnType]Arg) Arg {
	var val string
	switch typ.(type) {
	/* see google syzkaller issue 162. We prevent issuing a returnArg for lenType
	because it causes the fuzzer to crash when mutating programs with read, write, pread64, pwrite64
	*/
	case *LenType:
		return nil
	default:
	}

	if len(strace_arg) == 0 || strace_arg == "nil" {
		return nil
	}
	if strace_arg[0] == '&' {
		val = parsePointerArg(strace_arg).Val
	} else {
		val = strace_arg
	}
	return_var := returnType{
		Type: getType(typ),
		Val:  val,
	}
	if arg, ok := (*return_vars)[return_var]; ok {
		if arg != nil {
			return resultArg(typ, arg, typ.Default())
		}
	}

	return nil
}

func addr(s *domain.State, typ Type, size uint64, data Arg) (Arg, []*Call, error) {
	/*
		npages := (size + pageSize - 1) / pageSize
		fmt.Println("NPAGES: %d, %s", npages, typ.Name())
		if npages == 0 {
			npages = 1
		}
		for i := uint64(0); i < maxPages-npages; i++ {
			free := true
			for j := uint64(0); j < npages; j++ {
				if s.Pages[i+j] {
					free = false
					break
				}
			}
			if !free {
				continue
			}


			for j := uint64(0); j < npages; j++ {
				s.Pages[i+j] = true
			}
			// found a free memory section, let's mmap
			c := createMmapCall(i, npages)
			arg, calls := pointerArg(typ, i, 0, 0, data), []*Call{c}
			return arg, calls
		}
	*/
	arg := pointerArg(typ, uint64(0), 0, 0, data)
	s.Tracker.AddAllocation(s.CurrentCall, size, arg)
	return arg, nil, nil
	/*
	pages, offset, should_allocate, err := s.AllocateMemory(int(size))
	if err != nil {
		return nil, nil, err
	}
	if len(pages) == 1 {
		var c []*Call = nil
		if should_allocate {
			c = []*Call{createMmapCall(uint64(pages[0]), uint64(1))}
		}
		arg, calls := pointerArg(typ, uint64(pages[0]), offset, 0, data), c
		return arg, calls, nil
	} else {
		c := createMmapCall(uint64(pages[0]), uint64(len(pages)))
		args, calls := pointerArg(typ, uint64(pages[0]), 0, 0, data), []*Call{c}
		return args, calls, nil
	}
	*/
	//return r.randPageAddr(s, typ, npages, data, false), nil
}

func randPageAddr(s *domain.State, typ Type, npages uint64, data Arg, vma bool) Arg {
	poolPtr := pageStartPool.Get().(*[]uint64)
	starts := (*poolPtr)[:0]
	for i := uint64(0); i < maxPages-npages; i++ {
		busy := true
		for j := uint64(0); j < npages; j++ {
			if !s.Pages[i+j] {
				busy = false
				break
			}
		}
		// TODO: it does not need to be completely busy,
		// for example, mmap addr arg can be new memory.
		if !busy {
			continue
		}
		starts = append(starts, i)
	}
	*poolPtr = starts
	pageStartPool.Put(poolPtr)
	var page uint64
	if len(starts) != 0 {
		//page = starts[r.rand(len(starts))]
		page = starts[0]
	} else {
		page = uint64(rand.Int63n(int64(maxPages - npages)))
	}
	if !vma {
		npages = 0
	}
	return pointerArg(typ, page, 0, npages, data)
}

func getType(typ Type) string {
	switch a := typ.(type) {
	case *ResourceType:
		return "ResourceType" + a.Desc.Kind[0]
	case *BufferType:
		return "BufferType"
	case *VmaType:
		return "VmaType"
	case *FlagsType:
		return "FlagsType"
	case *ConstType:
		return "ConstType"
	case *IntType:
		return "IntType"
	case *ProcType:
		return "ProcType"
	case *ArrayType:
		return "ArrayType"
	case *StructType:
		return "StructType"
	case *UnionType:
		return "UnionType"
	case *PtrType:
		return "PtrType"
	case *LenType:
		return "LenType"
	case *CsumType:
		return "CsumType"
	default:
		panic("unknown argument type")
	}
}

func parsePointerArg(p string) pointer {
	if p[0:int(math.Min(2, float64(len(p))))] == "0x" {
		return pointer{p, ""}
	}
	if p[0] != '&' {
		return pointer{"", p}
	}

	/* else pointer is in format &addr=val */
	s := strings.SplitN(p, "=", 2)
	addr, val := s[0], s[1]
	if addr[0] == '&' {
		return pointer{addr[1:], val}
	} else {
		return pointer{addr, val}
	}
}

func (p pointer) String() string {
	return fmt.Sprintf("&%v=%v", p.Addr, p.Val)
}

func failf(msg string, args ...interface{}) {
	fmt.Fprintf(os.Stderr, msg+"\n", args...)
	os.Exit(1)
}

func extractVal(flags string, mode string, consts *map[string]uint64) (uint64, error) {
	var val uint64 = 0
	var err error
	var base int = 0

	if res, err := strconv.ParseUint(flags, 0, 64); err == nil {
		return res, nil
	}

	for _, or_op := range strings.Split(flags, "|") {
		var and_val uint64 = 0xFFFFFFFFFFFFFFFF
		for _, and_op := range strings.Split(or_op, "&") {
			c, ok := val_from_const(and_op, consts)
			fmt.Printf("c: %v\n", c)
			if !ok { // const doesn't exist, just return 0
				fmt.Printf("c: %s\n", and_op)
				if mode == "mode" {
					base = 8
				}
				c, err = strconv.ParseUint(and_op, base, 64) //this could be an octal
				if err != nil {
					return 0, errors.New("constant not found: " + and_op)
				}
			}
			and_val &= c
		}
		val |= and_val
	}
	return val, nil
}

/* Arg helper functions */

func commonArg(t Type) ArgCommon {
	common := ArgCommon{}
	common.AddType(t)
	return common
}

func groupArg(t Type, inner []Arg) Arg {

	return &GroupArg{ArgCommon: commonArg(t), Inner: inner}
}

func pointerArg(t Type, page uint64, off int, npages uint64, obj Arg) Arg {
	return &PointerArg{ArgCommon: commonArg(t), PageIndex: page, PageOffset: off, PagesNum: npages, Res: obj}
}

func constArg(t Type, v uint64) Arg {
	return &ConstArg{ArgCommon: commonArg(t), Val: v}
}

func dataArg(t Type, data []byte) Arg {
	return &DataArg{ArgCommon: commonArg(t), Data: append([]byte{}, data...)}
}

func unionArg(t Type, opt Arg, typ Type) Arg {
	return &UnionArg{ArgCommon: commonArg(t), Option: opt, OptionType: typ}
}

func resultArg(t Type, r Arg, v uint64) Arg {
	arg := &ResultArg{ArgCommon: commonArg(t), Res: r, Val: v}
	if r == nil {
		return arg
	}
	if used, ok := r.(ArgUsed); ok {
		if *used.Used() == nil {
			*used.Used() = make(map[Arg]bool)
		}
		if (*used.Used())[arg] {
			panic("already used")
		}
		(*used.Used())[arg] = true
	}
	return arg
}

func returnArg(t Type) Arg {
	return &ReturnArg{ArgCommon: commonArg(t)}
}

/* Misc Helpers */

func uintToVal(s string) (uint64, error) {
	var val uint64

	if strings.Contains(s, "*") {
		expression := strings.Split(s, "*")
		val = 1
		for _, v := range expression {
			v_parsed, ok := strconv.ParseInt(v, 0, 64)
			if ok != nil {
				failf("error evaluating expression %v\n", s)
			}
			val *= uint64(v_parsed)
		}
		return val, nil
	}
	if i, e := strconv.ParseInt(s, 0, 64); e == nil {
		return uint64(i), nil
	} else {
		return 0, e
	}
}

func parseIpV6(typ Type, ip string) (Arg, Type) {
	var optType Type
	switch b := typ.(type) {
	case *UnionType:
		if strings.Compare(ip, "\"::1\"") == 0 {
			//Loopback address and we are parsing into ipv6_addr_loopback
			optType = b.Fields[3]
			switch a := optType.(type) {
			case *StructType:
				a0 := a.Fields[0].(*ConstType)
				a1 := a.Fields[1].(*ConstType)
				/*
				a2 := a.Fields[2].(*ArrayType)
				a3 := a.Fields[3].(*ProcType)
				a4 := a.Fields[4].(*ConstType)
				*/
				a0_arg := constArg(a0, a0.Val)
				a1_arg := constArg(a1, a1.Val)
				/*
				arr_arg := make([]Arg, 12)
				for i, _ := range arr_arg {
					arr_arg[i] = constArg(a2.Type, 0)
				}
				a2_arg := groupArg(a2, arr_arg)
				a3_arg := constArg(a3, 0)
				a4_arg := constArg(a4, 0)
				*/
				return groupArg(a, []Arg{a0_arg, a1_arg}), optType
			default:
				failf("inner option not a structType\n")
			}

		} else if strings.Compare(ip, "\"::\"") == 0 {
			//We have 0.0.0.0 and we are parsing into ipv6_addr_empty in sys/vnet.txt
			optType = b.Fields[0]

			switch a := optType.(type) {
			case *StructType:
				arrType := a.Fields[0].(*ArrayType)
				inner_args := make([]Arg, 16)
				for i, _ := range inner_args {
					inner_args[i] = constArg(arrType.Type, 0)
				}
				arrArg := groupArg(arrType, inner_args)
				return groupArg(a, []Arg{arrArg}), optType
			default:
				fmt.Printf("DEFAULT TYPE FOR EMPTY: %s\n", optType.Name())
			}
		} else {
			optType = b.Fields[1]
			switch a := optType.(type) {
			case *StructType:
				a0 := a.Fields[0].(*ConstType)
				a1 := a.Fields[1].(*ConstType)
				a2 := a.Fields[2].(*ArrayType)
				a3 := a.Fields[3].(*ProcType)
				a4 := a.Fields[4].(*ConstType)
				a0_arg := constArg(a0, uint64(0xfe))
				a1_arg := constArg(a1, uint64(0x80))
				arr_arg := make([]Arg, 12)
				for i, _ := range arr_arg {
					arr_arg[i] = constArg(a2.Type, 0)
				}
				a2_arg := groupArg(a2, arr_arg)
				a3_arg := constArg(a3, 0)
				a4_arg := constArg(a4, uint64(0xaa))
				return groupArg(a, []Arg{a0_arg, a1_arg, a2_arg, a3_arg, a4_arg}), optType
			}

		}
	default:
		break

	}
	return nil, nil

}

func preProcessStructs(typ prog.Type, strace_arg *string){
	switch typ.Name() {
	case "itimerval":
		PreProcessItimerval(strace_arg)
	default:
		return
	}
	return
}

func parseStructs(typ prog.Type, strace_arg string,
			consts *map[string]uint64,
			return_vars *map[returnType]Arg,
			line *sparser.OutputLine,
			s *domain.State) (Arg, []*Call, error) {
	fmt.Printf("Type name: %s\n", typ.Name())
	is_nil := (strace_arg == "nil" || len(strace_arg) == 0)
	if is_nil {
		return DefaultArg(typ), nil, nil
	}
	switch typ.Name() {
	case "timeval":
		return ParseTimeval(typ, strace_arg, consts, return_vars, line, s)
	case "icmp_filter":
		return ParseIcmpFilter(typ, strace_arg, consts, return_vars, line, s)
	default:
		return defaultParseStruct(typ, strace_arg, consts, return_vars, line, s)
	}
}

func defaultParseStruct(typ prog.Type, strace_arg string,
			consts *map[string]uint64,
			return_vars *map[returnType]prog.Arg,
			line *sparser.OutputLine,
			s *domain.State) (arg prog.Arg, calls []*Call, err error) {
	a := typ.(*StructType)
	name, val := "nil", "nil"
	struct_args := make([]string, 0)
	if strace_arg != "nil" && len(strace_arg) >= 2 {
		strace_arg = strace_arg[1 : len(strace_arg)-1]
	}
	fmt.Printf("StructType %v\n", a.TypeName)

	is_nil := (strace_arg == "nil" || len(strace_arg) == 0)
	if !is_nil {
		for len(strace_arg) > 0 {
			param, rem := ident(strace_arg)
			strace_arg = rem
			struct_args = append(struct_args, param)
		}
		fmt.Printf("struct_args: %v\n", struct_args)
	}

	args := make([]Arg, 0)
	fmt.Println(a.TypeName, a.FldName)
	fmt.Println(len(a.Fields))

	field_order := make([]int, len(a.Fields))
	for i, _ := range field_order {
		//Usual case where Syzkaller and Strace have sync'd fields
		field_order[i] = i
	}
	fmt.Printf("STRUCT TYPE NAME: %s\n", typ.Name())
	if field_mapping, ok := Structs_with_reordered_fields[typ.Name()]; ok {
		//We have a special struct where strace has a different field order than syzkaller
		field_order = field_mapping

	}
	j := 0 //Some of the struct fields are pads so they don't correspond to strace args
	for i, arg_type := range a.Fields {
		fmt.Printf("i: %d, arg type: %v, is_nil: %b\n", i, arg_type, is_nil)
		if prog.IsPad(arg_type) {
			fmt.Printf("Is pad generating default arg in struct\n")
			args = append(args, DefaultArg(arg_type))
			continue
		}
		if !is_nil { // if nil, we need to generate nil values for entire struct
			if j < len(struct_args) {
				fmt.Printf("j < len(struct_args): %d\n", j)
				//For pselect6, the fd_set just returns an array with the fd mask
				//However, syzkaller has fd_set as a struct of 8 longs. If there are more
				//Fields than what strace gives us then we just keep val "nil"
				var should_parse bool = true
				if a.Dir() == DirOut {
					switch arg_type.(type) {
					case *ResourceType:
					default:
						should_parse = false
					}
				}
				if should_parse {
					struct_arg := struct_args[field_order[j]]
					fmt.Printf("should parse: %s\n", struct_arg)
					if strings.Contains(struct_arg, "=") && !IsTypeChar(struct_arg[0]){
						param := strings.SplitN(struct_arg, "=", 2)
						name, val = param[0], param[1]
					} else {
						name, val = "<missing>", struct_arg
					}
				}

			} else {
				//Strace doesn't provide any more arguments but the struct expects some.
				// Most likely padding so we just generate a default argument
				fmt.Printf("APPENDING DEFAULT ARG j > len(struct_args)")
				args = append(args, DefaultArg(arg_type))
				continue
			}
		}

		/* If there is a function embedded in the struct
		See ltp_accept4_01 line 50 for example
		*/
		if len(val) > 0 && val[len(val)-1] == ')' {
			inner_arg := parseInnerCall(val, arg_type, line, consts, return_vars, s)
			args = append(args, inner_arg)
			j+=1
			continue
		}

		if (len(struct_args) > i) {
			fmt.Printf("generating arg (%v) for struct type %v, field: %v, argtype: %v :%v, val: %v\n", i, a.Name(), name, arg_type, struct_args[j], val)
		}
		inner_arg, inner_calls, err_ := parseArg(arg_type, val, consts, return_vars, line, s)
		if err_ != nil {
			fmt.Printf("RETURNING FROM ERROR IN PARSE STRUCT: %s\n", err_.Error())
			err = err_
			j+=1
			return
		}

		/* cache value */
		if !is_nil {
			should_cache := true
			if a.Dir() == DirOut {
				switch arg_type.(type) {
				case *ResourceType:
				default:
					should_cache = false
				}
			}
			if should_cache {
				return_var := returnType{
					getType(arg_type),
					val,
				}
				switch arg_type.(type) {
				/* check for edge null conditions */
				case *StructType, *ArrayType, *BufferType, *UnionType:
				default:
					cache(return_vars, return_var, inner_arg, false)
				}
			}

		}
		args = append(args, inner_arg)
		calls = append(calls, inner_calls...)
		j+=1
	}
	fmt.Printf("ARG LEN: %d\n", len(args))
	arg = groupArg(a, args)
	return arg, calls, nil
}

func IsTypeChar(c byte) bool{
	ret := false
	switch c {
	case '{':
		ret = true
	case '[':
		ret = true
	case '"':
		ret = true
	}
	return ret
}

/* pack into corpus.db */


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
