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
	sanitizedLines := lines
	for i, line := range sanitizedLines {
		if line.Paused {
			fmt.Printf("Paused: %s %d %v\n", line.FuncName, i, line.Pid)
			for j := 0; j < len(lines)-i; j++ {
				if lines[i+j].Resumed && lines[i+j].Pid == line.Pid {
					if line.FuncName == "clone" && lines[i+j].Result == "?" {
						//The clone is going to be restarted so we should delete the paused and resumed portions
						fmt.Println("FOUND BAD CLONE")
						sanitizedLines = append(sanitizedLines[:i], append(sanitizedLines[i+1:i+j], sanitizedLines[i+j+1:]...)...)
						break
					}
					fmt.Printf("line[%d], result: %s, conents:%v\n", i+j, lines[i+j].Result, lines[i+j])
					lines[i].Args = append(lines[i].Args, lines[i+j].Args...)

					//If the program is unfinished it needs the result from the finished part
					lines[i].Result = lines[i+j].Result
					//Delete the resumed line
					sanitizedLines = append(sanitizedLines[:i+j], sanitizedLines[i+j+1:]...)
					break
				}
			}
		} else {
			if line.FuncName == "clone" && line.Result == "?" {
				//The clone is going to be restarted so we should delete this line
				sanitizedLines = append(sanitizedLines[:i], sanitizedLines[i+1:]...)
			}
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
	file, dir, configLocation := *flagFile, *flagDir, *flagConfig
	getTraces, distill := *flagGetTraces, *flagDistill
	/* if ((file == "" && dir == "" )|| (file != "" && dir != "")) {
			usage()
	} */
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
	for i, filename := range strace_files {
		if i < *flagSkip {
			continue
		}
		fmt.Printf("==========File %v PARSING: %v=========\n", i, filename)
		trace := NewTrace()
		straceCalls := parseStrace(filename)

		fmt.Println("==========Finished Parsing============")
		straceCalls = trace.Sanitize(straceCalls)
		trace.Parse(straceCalls)
		fmt.Fprintf(os.Stderr, "Number of pids: %d\n", len(trace.ptree))
		for pid, childPids := range trace.ptree {
			fmt.Printf("pid: %v\n", pid)
			fmt.Printf("childPids: %v", childPids)
			for _, child := range childPids {
				fmt.Printf("Parent pid: %v, Child Pid: %v\n", pid, child)
			}
		}
		var parsedProg *prog.Prog
		for pid, _ := range trace.progs {
			fmt.Printf("TRACE PROGS PIDS: %v\n", pid)
			lines := trace.progs[pid]
			if len(lines) > 250 {
				fmt.Printf("Pid has more than 250 calls: %v, %d", pid, len(lines))
				continue
			}
			s := domain.NewState(target) /* to keep track of resources and memory */
			parsedProg, err = parse(target, lines, s, &consts, &seeds)
			if err != nil {
				fmt.Printf("Error parsing program: %s\n", err.Error())
				continue
			}
			if !distill {
				s.Tracker.FillOutMemory(parsedProg)
				totalMemory := s.Tracker.GetTotalMemoryNeeded(parsedProg)
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
				fmt.Printf("Error validating %v\n", "something")
				failf(err.Error())
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
	for call, _ := range seen_calls {
		fmt.Printf("\"%s\",", call)
	}
	fmt.Printf("\n");

	if distill {
		fmt.Fprintf(os.Stderr, "distilling using %s method\n", config.DistillConf.Type)
		distiller_.Add(seeds)
		distilled := distiller_.Distill(progs)

		for i, progd := range distilled {
			if err := progd.Validate(); err != nil {
				fmt.Printf("Error validating %v\n", progd)
				failf(err.Error())
				break
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
		seeds.Add(seed)
	}
	memory := s.Tracker.GetTotalMemoryNeeded(prog)
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

	/* adjust functions to fit syzkaller standards */
	process(target, line, consts, return_vars)
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

	// add calls to our program

	for _, c := range calls {
		// TODO: sanitize c?
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
		if strings.Contains(line.FuncName, "$inet") && call == "inet_addr" {
			var optType Type
			var inner_arg Arg
			args[0] = args[0][1 : len(args[0])-1] // strip quotes
			if args[0] == "0.0.0.0" {
				optType = a.Fields[0]
				inner_arg = constArg(optType, uint64(0x00000000))
			} else if args[0] == "127.0.0.1" {
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
			failf("failed to parse inner call %v\n", val)
		}
	case "htonl":
		if i, err := strconv.ParseUint(args[0], 0, 32); err == nil {
			arg = constArg(typ, uint64(Htonl(uint32(i))))
		} else {
			failf("failed to parse inner call %v\n", val)
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

func process(target *Target, line *sparser.OutputLine, consts *map[string]uint64, return_vars *map[returnType]Arg) {
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
			return
		}

		if label, ok := Getsockopt_labels[variant]; ok {
			line.FuncName += label
		} else if _, ok := (*consts)[variant.B]; ok {
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
		} else if _, ok := (*consts)[variant.B]; ok {
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
		if strings.Contains(line.Args[1], "RTMIN") || strings.Contains(line.Args[1], "RT_3") {
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
		} else {
			failf("unknown prctl variant %v\n", line.Unparse())
		}
	default:
	}
}

func parseSpecialStructs(typ Type, strace_arg string,
	consts *map[string]uint64,
	return_vars *map[returnType]Arg,
	line *sparser.OutputLine) (arg Arg, calls []*Call) {
	st := typ.(*StructType)
	fmt.Printf("TYPE NAME: %s\n", st.TypeName)
	if strings.Compare(typ.Name(), "timeval") == 0 {
		//This is a particular field of the socket operation with optname SO_SNDTIMEO
		//inner_args := make([]Arg, 0)

		if strings.Contains(strace_arg, "\"") {
			strace_arg = strace_arg[1 : len(strace_arg)-1]
			split := strings.Split(strace_arg, "\\")
			fmt.Printf("SPECIFIC STRUCT SPLIT %v\n", split)
			timeout_secs, err := strconv.ParseUint(strings.Split(strace_arg, "\\")[1], 10, 64)
			if err != nil {
				panic(fmt.Sprintf("Error parsing timeout_secs in specific structs: %s\n", err.Error()))
			}
			timeout_usecs := uint64(0)
			fmt.Printf("FIELD TYPE NAME:%s\n", st.Fields[0])
			arg = groupArg(typ, []Arg{resultArg(st.Fields[0], nil, timeout_secs), resultArg(st.Fields[1], nil, timeout_usecs)})
			calls = nil
			return
		} else {
			return nil, nil
		}
	}
	return nil, nil
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
		if v, ok := (*consts)[strace_arg]; ok {
			return resultArg(a, nil, uint64(v)), nil, nil
		}
		//Need to parse as int because we may have negative file descriptor
		extracted_int, err := strconv.ParseInt(strace_arg, 0, 64)
		if err != nil {
			failf("Error parsing resource arg %s for call %s, desc: %s\n", strace_arg, call, err.Error())
		}
		// TODO: special values only
		arg, calls = resultArg(a, nil, uint64(extracted_int)), nil
		err = nil
	case *BufferType:
		fmt.Printf("Parsing Buffer Type: %v\n", strace_arg)

		if a.Dir() != DirOut && strace_arg != "nil" {
			var buffer []byte
			switch a.Kind {
			case BufferFilename, BufferString:
				fmt.Printf("BUFFER BLOB STRING\n")

				buffer = make([]byte, len(strace_arg)-2)
			case BufferBlobRand:
				fmt.Printf("BUFFER BLOB RAND\n")
				size := len(strace_arg) - 2
				buffer = make([]byte, size)
			case BufferBlobRange:
				fmt.Printf("BUFFER BLOB RANGE\n")
				size := rand.Intn(int(a.RangeEnd)-int(a.RangeBegin)+1) + int(a.RangeBegin)
				fmt.Printf("SIZE: %d\n", size)
				buffer = make([]byte, size)
			default:
				failf("unexpected buffer type. call %v arg %v", call, strace_arg)
			}
			fmt.Printf("Strace Arg Len: %d\n", len(strace_arg))
			strace_arg_arr := []byte(strace_arg[1 : len(strace_arg)-1])
			for i := 0; i < len(buffer); i++ {
				if i < len(strace_arg_arr) {
					buffer[i] = strace_arg_arr[i]
				}
			}
			arg = dataArg(a, buffer)
		} else {
			if strace_arg != "nil" && strace_arg[0] == '"' { /* make buffer size of given string */
				return dataArg(a, make([]byte, len(strace_arg)-1)), nil, nil
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
		if strace_arg == "NULL" && a.IsOptional {
			var size uint64 = 0
			switch b := a.Type.(type) {
			case *BufferType:
				if !b.Varlen() {
					size = b.Size()
				}
			default:
				size = a.Type.Size()
			}
			arg, calls, err = addr(s, a, size, nil)
			if err != nil {
				return
			}
			return arg, calls, nil
		}

		if strace_arg == "NULL" && !a.IsOptional {
			strace_arg = "nil" // just render the default value
		}

		ptr := parsePointerArg(strace_arg)
		if ptr.Val == "" {
			ptr.Val = "nil" // TODO: this is really bad, consider refactoring parseArg
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
		fmt.Printf("Parsing Const type %v\n", strace_arg)
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
		if strace_arg == "nil" {
			if a.Kind == ArrayRangeLen {
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
		arg, calls = parseSpecialStructs(typ, strace_arg, consts, return_vars, line)
		if arg != nil {
			fmt.Printf("NON NIL ARG: %v\n", arg)
			return
		}
		name, val := "nil", "nil"
		struct_args := make([]string, 0)
		if strace_arg != "nil" {
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

		for i, arg_type := range a.Fields {
			fmt.Printf("%v: %v\n", i, a.Fields[i])
			if !is_nil { // if nil, we need to generate nil values for entire struct
				if i < len(struct_args) {
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
						struct_arg := struct_args[field_order[i]]
						if strings.Contains(struct_arg, "=") {
							param := strings.SplitN(struct_arg, "=", 2)
							name, val = param[0], param[1]
						} else {
							name, val = "<missing>", struct_arg
						}
					}

				}
			}

			/* If there is a function embedded in the struct
			See ltp_accept4_01 line 50 for example
			*/
			if val[len(val)-1] == ')' {
				inner_arg := parseInnerCall(val, arg_type, line, consts, return_vars, s)
				args = append(args, inner_arg)
				continue
			}

			fmt.Printf("generating arg (%v) for struct type %v, field: %v\n", i, a.Name(), name)
			inner_arg, inner_calls, err_ := parseArg(arg_type, val, consts, return_vars, line, s)
			if err_ != nil {
				fmt.Printf("RETURNING FROM ERROR IN PARSE STRUCT: %s\n", err_.Error())
				err = err_
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
		}
		arg = groupArg(a, args)
		return arg, calls, nil
	case *UnionType:
		fmt.Printf("Parsing unionType for: %v with type: %s\n", strace_arg, a.TypeName)
		optType := a.Fields[0]
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

func ident(arg string) (string, string) {
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
					sawSpecialChar = true
					continue
				}
				if len(s) == 0 && arg[i] == ',' {
					break
				}
				if arg[i] == '[' || arg[i] == '{' || arg[i] == '(' {
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
					s, r = s.Pop()
					if r != '(' {
						failf("illegal argument format %v\n", arg)
					}
					continue
				}
			} else {
				if arg[i] == '"' {
					if sawSpecialChar {
						//We have a nested string we can continue
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

	for _, or_op := range strings.Split(flags, "|") {
		var and_val uint64 = 0xFFFFFFFFFFFFFFFF
		for _, and_op := range strings.Split(or_op, "&") {
			c, ok := (*consts)[and_op]
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
				a2 := a.Fields[2].(*ArrayType)
				a3 := a.Fields[3].(*ProcType)
				a4 := a.Fields[4].(*ConstType)
				a0_arg := constArg(a0, a0.Val)
				a1_arg := constArg(a1, a1.Val)
				arr_arg := make([]Arg, 12)
				for i, _ := range arr_arg {
					arr_arg[i] = constArg(a2.Type, 0)
				}
				a2_arg := groupArg(a2, arr_arg)
				a3_arg := constArg(a3, 0)
				a4_arg := constArg(a4, 0)
				return groupArg(b, []Arg{a0_arg, a1_arg, a2_arg, a3_arg, a4_arg}), optType
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
