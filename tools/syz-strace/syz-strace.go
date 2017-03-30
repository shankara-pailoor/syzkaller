package main

import (
	sparser "github.com/mattrco/difftrace/parser"
	"os"
	"fmt"
	"strings"
	"github.com/google/syzkaller/sys"
	. "github.com/google/syzkaller/prog"
	"path/filepath"
	"bufio"
	"strconv"
	"reflect"
	"io/ioutil"
	"github.com/google/syzkaller/db"
	"github.com/google/syzkaller/hash"
	. "github.com/google/syzkaller/tools/syz-structs"
	"sync"
	"math/rand"
	"errors"
	"math"
	"flag"
)

const (
	arch = "amd64"
	maxLineLen = 256 << 10
	pageSize   = 4 << 10
	maxPages   = 4 << 10
)

var pageStartPool = sync.Pool{New: func() interface{} { return new([]uintptr) }}


type pointer struct {
	Addr	string
	Val	string
}

type returnType struct {
	Type 	string
	Val  	string
}

type state struct {
	files     map[string]bool
	resources map[string][]*Arg
	strings   map[string]bool
	pages     [maxPages]bool
}

var (
	flagFile = flag.String("file", "", "file to parse")
	flagDir = flag.String("dir", "", "directory to parse")
	flagSkip = flag.Int("skip", 0, "how many to skip")
)

func usage() {
	fmt.Fprintf(os.Stderr, "usage:\n")
	fmt.Fprintf(os.Stderr, "  ./bin/syz-strace -file filename\n")
	fmt.Fprintf(os.Stderr, "  ./bin/syz-strace -dir dirname\n")
	os.Exit(1)
}

func main() {
	flag.Parse()
	file, dir := *flagFile, *flagDir
	if ((file == "" && dir == "" )|| (file != "" && dir != "")) {
		usage()
	}

	strace_files := make([]string, 0)

	if (file != "") {
		strace_files = append(strace_files, file)
	}

	if (dir != "") {
		files, err := ioutil.ReadDir(dir)
		if err != nil {
			failf(err.Error())
		}
		for _, f := range files {
			strace_files = append(strace_files, filepath.Join(dir, f.Name()))
		}
	}

	fmt.Printf("strace_files: %v\n", strace_files)

	os.Mkdir("serialized", 0750)
	consts := readConsts(arch)

	for i,filename := range strace_files {
		if i < *flagSkip {
			continue
		}
		fmt.Printf("==========File %v PARSING: %v=========\n", i, filename)
		parse(filename, &consts)
		fmt.Printf("==============================\n\n")
	}


	fmt.Println("Done, now packing into corpus.db")
	pack("serialized", "corpus.db")
}

func parseCall(line *sparser.OutputLine, consts *map[string]uint64,
		return_vars *map[returnType]*Arg, s *state, prog *Prog) {
	if _, ok := Unsupported[line.FuncName]; ok {
		return // don't parse unsupported syscalls
	}

	/* adjust functions to fit syzkaller standards */
	process(line, consts, return_vars)

	meta := sys.CallMap[line.FuncName]
	if meta == nil {
		failf("unknown syscall %v\n", line.Unparse())
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
	var calls []*Call
	var strace_arg string
	for i, typ := range meta.Args {
		if (i < len(line.Args)) {
			strace_arg = line.Args[i]
		} else {
			fmt.Printf("arg %v %v not present, using nil\n", i, typ.Name())
			strace_arg = "nil"
		}

		parsedArg, calls1 := parseArg(typ, strace_arg, consts, return_vars, line, s)
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
	for _,c := range calls {
		// TODO: sanitize c?
		s.analyze(c)
		prog.Calls = append(prog.Calls, c)
	}

	fmt.Println("\n---------done parsing line--------\n")

}

func parseInnerCall(val string, typ sys.Type, line *sparser.OutputLine, consts *map[string]uint64,
 		    return_vars *map[returnType]*Arg, s *state) *Arg {

	fmt.Println("---------Parsing Inner Call Args-----------")
	fmt.Println(val)

	i := 0
	for val[i] != '(' {
		i++
	}
	call, arg_str := val[:i], val[i:] // split into form <call>=(<args>)
	arg_str = arg_str[1:len(arg_str)-1] // strip parentheses

	args := make([]string, 0)

	for len(arg_str) > 0 {
		param, rem := ident(arg_str)
		arg_str = rem
		args = append(args, param)
	}
	fmt.Printf("call %v\n", call)
	fmt.Printf("args: %v\n", args)

	switch a := typ.(type) {
	/* just choose max allowed for proc args */
	case *sys.ProcType:
		return constArg(a, uintptr(a.ValuesPerProc - 1))
	case *sys.UnionType:
		/* I know this is horrible but there's no other way to know the union type! :( */
		if strings.Contains(line.FuncName, "$inet") && call == "inet_addr" {
			var optType sys.Type
			var inner_arg *Arg
			args[0] = args[0][1:len(args[0])-1] // strip quotes
			if args[0] == "0.0.0.0" {
				optType = a.Options[0]
				inner_arg = constArg(optType, uintptr(0x00000000))
			} else if args[0] == "127.0.0.1" {
				optType = a.Options[1]
				inner_arg = constArg(optType, uintptr(0x7f000001))
			} else if args[0] == "255.255.255.255" {
				optType = a.Options[2]
				inner_arg = constArg(optType, uintptr(0xffffffff))
			} else {
				failf("unsupported inet_addr %v in %v\n", args[0], val)
			}
			return unionArg(a, inner_arg, optType)
		} else if strings.Contains(line.FuncName, "$inet6") && call == "inet_pton" {
			var optType sys.Type
			var inner_arg *Arg
			if args[1] == "\"::1\"" {
				optType = a.Options[1]
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
				inner_arg = groupArg(b, []*Arg{a0_arg, a1_arg})
			default:
				failf("inner option not a structType %v\n", line.Unparse())
			}
			return unionArg(a, inner_arg, optType)
		} else {
			fmt.Printf("`%v`\n", args[0])
			failf("unexpected uniontype call %v parsing arg %v\n", line.Unparse(), val)
		}
	default:
	}

	var arg *Arg
	switch call {
	case "htons":
		if i,err := strconv.ParseUint(args[0], 0, 16); err == nil {
			arg = constArg(typ, uintptr(Htons(uint16(i))))
		} else {
			failf("failed to parse inner call %v\n", val)
		}
	case "htonl":
		if i,err := strconv.ParseUint(args[0], 0, 32); err == nil {
			arg = constArg(typ, uintptr(Htonl(uint32(i))))
		} else {
			failf("failed to parse inner call %v\n", val)
		}
	case "inet_addr":
		args[0] = args[0][1:len(args[0])-1] // strip quotes
		if args[0] == "0.0.0.0" {
			arg = constArg(typ, uintptr(0x00000000))
		} else if args[0] == "127.0.0.1" {
			arg = constArg(typ, uintptr(0x7f000001))
		} else if args[0] == "255.255.255.255" {
			arg = constArg(typ, uintptr(0xffffffff))
		} else {
			failf("unsupported inet_addr %v in %v\n", args[0], val)
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

func parse(filename string, consts *map[string]uint64) {
	prog :=  new(Prog)
	f, err := os.Open(filename)
	if err != nil {
		fmt.Printf("failed to open file: %v\n", filename)
		failf(err.Error())
	}
	p := sparser.NewParser(f)
	return_vars := make(map[returnType]*Arg)
	s := newState() /* to keep track of resources and memory */

	for {
		line, err := p.Parse()
		if err != nil {
			if err != sparser.ErrEOF {
				fmt.Println(err.Error())
			}
			break
		}

		parseCall(line, consts, &return_vars, s, prog)
	}
	if err := prog.Validate(); err != nil {
		fmt.Printf("Error validating %v\n", filename)
		failf(err.Error())
	}

	fmt.Printf("successfully parsed %v into program of length %v\n", filename, len(prog.Calls))

	s_name := "serialized/" + filepath.Base(filename)
	if err := ioutil.WriteFile(s_name, prog.Serialize(), 0640); err != nil {
		failf("failed to output file: %v", err)
	}
	fmt.Printf("serialized output to %v\n", s_name)
}

func cache(return_vars *map[returnType]*Arg, return_var returnType, arg *Arg, returned bool) bool {
	/* TODO: may want to have more fine-grained type for caching to reduce collisions.
	as of now we over-write any collision, but this may not be optimal behavior.
	 */

	if returned {
		fmt.Printf("caching %v %v\n", return_var, arg.Type.Name())
		(*return_vars)[return_var] = arg
		 return true
	}

	if _,ok := (*return_vars)[return_var]; !ok {
		fmt.Printf("caching %v %v\n", return_var, arg.Type.Name())
		(*return_vars)[return_var] = arg
		return true

	}
	return false
}

func process(line *sparser.OutputLine, consts *map[string]uint64, return_vars *map[returnType]*Arg) {
	switch line.FuncName {
	case "accept", "accept4":
		return_var := returnType{
			"ResourceType",
			line.Args[0],
		}
		if arg,ok := (*return_vars)[return_var]; ok {
			switch a := arg.Type.(type) {
			case *sys.ResourceType:
				if label,ok := Accept_labels[a.TypeName]; ok {
					line.FuncName = line.FuncName + label
					fmt.Printf("discovered accept type: %v\n", line.FuncName)
				} else {
					failf("unknown accept variant for type %v\nline: %v\n", a.TypeName, line.Unparse())
				}
			default:
				failf("return_var for accept is NOT a resource type %v\n", line.Unparse())
			}
		}
	case "bind", "connect":
		var m *map[string]string
		label := ""
		return_var := returnType{
			"ResourceType",
			line.Args[0],
		}
		if line.FuncName == "bind" {
			m = &Bind_labels
		} else {
			m = &Connect_labels
		}
		if arg,ok := (*return_vars)[return_var]; ok {
			switch a := arg.Type.(type) {
			case *sys.ResourceType:
				if label,ok = (*m)[a.TypeName]; ok {
					line.FuncName = line.FuncName + label
					fmt.Printf("discovered type: %v\n", line.FuncName)
				} else {
					failf("unknown variant for type %v\nline: %v\n", a.TypeName, line.Unparse())
				}
			default:
				failf("first arg is NOT a resource type %v\n", line.Unparse())
			}
		}

		if label == "$inet" || label == "$inet6" {
			line.Args[1] = strings.Replace(line.Args[1], "}", ", pad=nil", 1)
		}

	case "socket":
		if label,ok := Socket_labels[line.Args[0]]; ok {
			line.FuncName += label
		} else {
			failf("unrecognized set/getsockopt variant %v\n", line.Unparse())
		}
	case "getsockopt":
		fmt.Printf("argv1: %s\n", line.Args[1])
		line.Args[1] = SocketLevel_map[line.Args[1]] /*strace uses SOL levels */
		variant := Pair{line.Args[1],line.Args[2]}
		/* key collision, need to resolve manually */
		if line.Args[1] == "SOL_SOCKET" && line.Args[2] == "SO_PEERCRED" {
			if line.Args[3][0] == '"' {
				line.FuncName += "$sock_buf"
			} else {
				line.FuncName += "$sock_cred"
			}
			return
		}

		if label,ok := Getsockopt_labels[variant]; ok {
			line.FuncName += label
		} else if _,ok := (*consts)[variant.B]; ok {
			line.FuncName += ("$" + variant.B)
		} else {
			fmt.Printf("unrecognized set/getsockopt variant %v\n", line.Unparse())
		}
	case "setsockopt":
		fmt.Printf("setsockopt argv1: %s\n", line.Args[1])
		line.Args[1] = SocketLevel_map[line.Args[1]]
		variant := Pair{line.Args[1],line.Args[2]}

		fmt.Printf("variant: %v\n", variant)
		if label,ok := Setsockopt_labels[variant]; ok {
			line.FuncName += label
		} else if _,ok := (*consts)[variant.B]; ok {
			line.FuncName += ("$" + variant.B)
		} else {
			fmt.Printf("unrecognized set/getsockopt variant %v\n", line.Unparse())
		}
	case "fcntl":
		if label,ok := Fcntl_labels[line.Args[1]]; ok {
			line.FuncName += label
			if meta,ok := sys.CallMap[line.FuncName]; ok {
				if len(line.Args) < len(meta.Args) { /* third arg is missing, put in default */
					line.Args = append(line.Args, strconv.FormatUint(uint64(meta.Args[2].Default()), 10))
				}
			} else {
				failf("call not found: %v\n", line.FuncName)
			}
		} else {
			failf("unrecognized fcntl variant %v\n", line.Unparse())
		}
	case "sched_setaffinity":
		s := line.Args[2]
		if s[0] == '[' && s[len(s)-1] == ']' {
			line.Args[2] = s[1:len(s)-1]
		}
	case "capget":
		line.Args[1] = "[]"
	case "select":
		line.Args[1] = "[]" // TODO: can we work around?
	case "rt_sigaction":
		if len(line.Args) < 5 {
			line.Args = append(line.Args, "{fake=0}")
		}
		if line.Args[0] == "SIGRT_1" || line.Args[0] == "SIGRT_16" {
			min := int((*consts)["SIGRTMIN"])
			max := int((*consts)["SIGRTMAX"])
			line.Args[0] = strconv.Itoa(rand.Intn(max - min + 1) + min)
		}
		if strings.Contains(line.Args[1], "[ALRM]") {
			new := strings.Replace(line.Args[1], "[ALRM]", "{mask=14}", 1)
			line.Args[1] = new
		}
		line.Args[1] = strings.Replace(line.Args[1], "~[RTMIN RT_1]", "[]", 1)
	case "rt_sigprocmask":
		if strings.Contains(line.Args[1], "RTMIN") {
			line.Args[1] = "{mask=0x8001}"
		} else if strings.Contains(line.Args[1], "RTMAX") {
			line.Args[1] = "{mask=0xfffffffffffffffe}"
		} else if line.Args[1] == "NULL" {
			line.Args[1] = "[]"
		} else {
			failf("%v unexpected arg format for rt_sigprocmask", line.Args[1])
		}
	case "ioctl":
		candidateName := line.FuncName + "$" + line.Args[1]
		if _, ok := sys.CallMap[candidateName]; !ok {
			if _, ok = Ioctl_map[line.Args[1]]; ok {
			line.FuncName = line.FuncName + "$" + Ioctl_map[line.Args[1]]
			}
		} else {
			line.FuncName = line.FuncName + "$" + line.Args[1]
		}
	default:
	}
}



func parseArg(typ sys.Type, strace_arg string,
	      consts *map[string]uint64, return_vars *map[returnType]*Arg,
              line *sparser.OutputLine, s *state) (arg *Arg, calls []*Call) {
	call := line.FuncName
	fmt.Printf("-----Entering parseArg-------" +
		"\nparsing arg: %v" +
		"\nfor call: %v \n", strace_arg, call)
	// check if this is a return arg
	if arg := isReturned(typ, strace_arg, return_vars); arg != nil {
		fmt.Println("Discovered return type!")
		fmt.Println("\n-------exiting parseArg--------\n")
		return arg, nil
	}

	switch a := typ.(type) {
	case *sys.FlagsType:
		fmt.Printf("Call: %v\nparsing FlagsType %v\n", call, strace_arg)
		if strace_arg == "nil" {
			return constArg(a, a.Default()), nil
		}
		val, _ := extractVal(strace_arg, consts)
		arg, calls = constArg(a, uintptr(val)), nil
	case *sys.ResourceType:
		fmt.Printf("Resource Type: %v\n", a.Desc)
		// TODO: special parsing required if struct is type timespec or timeval
		if strace_arg == "nil" || a.Dir() == sys.DirOut {
			return constArg(a, a.Default()), nil
		}
		if v, ok := (*consts)[strace_arg]; ok {
			return constArg(a, uintptr(v)), nil
		}
		extracted_int, err := strconv.ParseInt(strace_arg, 0, 64)
		if err != nil {
			failf("Error converting int type for syscall: %s, %s", call, err.Error())
		}
		// TODO: special values only
		arg, calls = constArg(a, uintptr(extracted_int)), nil
	case *sys.BufferType:
		fmt.Printf("Parsing Buffer Type: %v\n", strace_arg)

		if a.Dir() != sys.DirOut && strace_arg != "nil" {
			arg = dataArg(a, []byte(strace_arg[1:len(strace_arg)-1]))
		} else {
			if strace_arg != "nil" && strace_arg[0] == '"' { /* make buffer size of given string */
				return dataArg(a, make([]byte, len(strace_arg)-1)), nil
			}

			switch a.Kind {
			case sys.BufferFilename, sys.BufferString:
				arg = dataArg(a, make([]byte, len(strace_arg)-1)) // -2 for the " "
			case sys.BufferBlobRand:
				size := rand.Intn(256)
				arg = dataArg(a, make([]byte, size))
			case sys.BufferBlobRange:
				size := rand.Intn(int(a.RangeEnd) - int(a.RangeBegin) + 1) + int(a.RangeBegin)
				arg = dataArg(a, make([]byte, size))
			default:
				failf("unexpected buffer type. call %v arg %v", call, strace_arg)
			}
		}
		return arg, nil
	case *sys.PtrType:
		fmt.Printf("Call: %s \n Pointer with inner type: %v\n", call, a.Type.Name())
		if strace_arg == "NULL" && a.IsOptional {
			arg, _ = addr(s, a, a.Type.Size(), nil)
			return arg, nil
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
			case *sys.IntType, *sys.LenType, *sys.CsumType, *sys.ResourceType:
				ptr.Val = ptr.Val[1:len(ptr.Val)-1]
			default:
			}
		}

		inner_arg, inner_calls := parseArg(a.Type, ptr.Val, consts, return_vars, line, s)

		/* cache this pointer value */
		switch a.Type.(type) {
		/* don't cache for these types */
		case *sys.PtrType, *sys.ArrayType, *sys.StructType, *sys.BufferType, *sys.UnionType:
		default:
			return_var := returnType{
				getType(a.Type),
				ptr.Val,
			}
			fmt.Printf("caching %v result for %v %v\n", return_var, call, a.Type.Name())
			cache(return_vars, return_var, inner_arg, false)
		}

		outer_arg, outer_calls := addr(s, a, inner_arg.Size(), inner_arg)
		inner_calls = append(inner_calls, outer_calls...)
		arg, calls = outer_arg, inner_calls
	case *sys.IntType:
		var extracted_int uint64
		var err error = nil
		if strace_arg == "nil" || a.Dir() == sys.DirOut {
			extracted_int = uint64(a.Default())
		} else {
			strace_arg = func () string {
					for _, macro := range Macros {
						if strings.Contains(strace_arg, macro) {
							return MacroExpand_map[macro](strace_arg)
						}
					}
					return strace_arg
			     }()
			extracted_int, err = uintToVal(strace_arg)
		}
		if err != nil { /* const */
			extracted_int, err = extractVal(strace_arg, consts)
		}
		if err != nil {
			failf("cannot parse IntType input %v\n", strace_arg)
		}
		fmt.Printf("Parsed IntType %v with val %v\n", strace_arg, int(extracted_int))
		arg, calls = constArg(a, uintptr(extracted_int)), nil
	case *sys.VmaType:
		fmt.Printf("VMA Type: %v Call: %s\n", strace_arg, call)
		npages := uintptr(1)
		// TODO: strace doesn't give complete info, need to guess random page range
		if a.RangeBegin != 0 || a.RangeEnd != 0 {
			npages = uintptr(int(a.RangeBegin)) + 1 // + r.Intn(int(a.RangeEnd-a.RangeBegin+1)))
		}
		arg := randPageAddr(s, a, npages, nil, true)
		//arg, calls = &Arg{Type: a, Val: uintptr(1), Kind: ArgPointer}, nil
		return arg, nil
	case *sys.ConstType:
		fmt.Printf("Parsing Const type %v\n", strace_arg)
		if a.Dir() == sys.DirOut {
			return constArg(a, a.Default()), nil
		}
		data, e := uintToVal(strace_arg)
		if e != nil {
			data, e = extractVal(strace_arg, consts)
		}
		if strace_arg == "nil" || e != nil {
			fmt.Printf("Creating constarg with val %v\n", a.Val)
			return constArg(a, a.Val), nil
		}
		fmt.Printf("Creating constarg with val %v\n", data)
		return constArg(a, uintptr(data)), nil
	case *sys.ProcType, *sys.LenType, *sys.CsumType:
		fmt.Println("Proc/Len/Csum Type")
		var data uint64
		var e error
		if strace_arg == "nil" {
			data = 0
		} else {
			data, e = uintToVal(strace_arg)
		}
		if e == nil {
			return constArg(a, uintptr(data)), nil
		}
		return constArg(a, 0), nil
	case *sys.ArrayType:
		var args []*Arg
		if strace_arg == "nil" {
			if a.Kind == sys.ArrayRangeLen {
				size := rand.Intn(int(a.RangeEnd) - int(a.RangeBegin) + 1) + int(a.RangeBegin)
				for i := 0; i < size; i++ {
					inner_arg, inner_calls := parseArg(a.Type, "nil", consts, return_vars, line, s)
					args = append(args, inner_arg)
					calls = append(calls, inner_calls...)
				}

			}
			return groupArg(typ, args), nil
		}
		// clip the square brackets
		strace_arg = strace_arg[1:len(strace_arg)-1]
		fmt.Printf("ArrayType %v\n", a.TypeName)

		for len(strace_arg) > 0 {
			param, rem := ident(strace_arg)
			strace_arg = rem
			inner_arg, inner_calls := parseArg(a.Type, param, consts, return_vars, line, s)
			args = append(args, inner_arg)
			calls = append(calls, inner_calls...)
		}
		arg = groupArg(typ, args)
	case *sys.StructType:
		name, val := "nil", "nil"
		struct_args := make([]string, 0)
		if strace_arg != "nil" {
			strace_arg = strace_arg[1:len(strace_arg) - 1]
		}
		fmt.Printf("StructType %v\n", a.TypeName)


		is_nil := (strace_arg == "nil" || len(strace_arg) == 0 || a.Dir() == sys.DirOut)
		if !is_nil {
			for len(strace_arg) > 0 {
				param, rem := ident(strace_arg)
				strace_arg = rem
				struct_args = append(struct_args, param)
			}
			fmt.Printf("struct_args: %v\n", struct_args)
		}

		args := make([]*Arg, 0)
		fmt.Println(a.TypeName, a.FldName)
		fmt.Println(len(a.Fields))
		for i, arg_type := range a.Fields {
			fmt.Printf("%v: %v\n", i, a.Fields[i])
			if !is_nil { // if nil, we need to generate nil values for entire struct
				struct_arg := struct_args[i]
				if strings.Contains(struct_arg, "=") {
					param := strings.SplitN(struct_arg, "=", 2)
					name, val = param[0], param[1]
				} else {
					name,val = "<missing>", struct_arg
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
			inner_arg, inner_calls := parseArg(arg_type, val, consts, return_vars, line, s)

			/* cache value */
			if !is_nil {
				return_var := returnType{
					getType(arg_type),
					val,
				}
				switch arg_type.(type) {
				/* check for edge null conditions */
				case *sys.StructType, *sys.ArrayType, *sys.BufferType, *sys.UnionType:
				default:
					cache(return_vars, return_var, inner_arg, false)
				}
			}
			args = append(args, inner_arg)
			calls = append(calls, inner_calls...)
		}
		arg = groupArg(a, args)
		return arg, calls
	case *sys.UnionType:
		fmt.Printf("Parsing unionType for: %v\n", strace_arg)
		optType := a.Options[0]
		opt, inner_calls := parseArg(optType, strace_arg, consts, return_vars, line, s)
		calls = append(calls, inner_calls...)
		arg = unionArg(a, opt, optType)
	default:
		fmt.Printf("Call: %s\n Arg: %v\n", call, typ)
		fmt.Printf("Args: %v\n", reflect.TypeOf(typ))
		panic("uncaught type")
	}

	fmt.Println("-------exiting parseArg--------")

	return arg, calls
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

		for ; i != len(arg) || len(s) != 0; i++ {
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
					failf("illegal argument format %v\n", arg)
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
		}
		return arg[j:i], arg[i:]
	}
	fmt.Printf("Error, invalid arg. Paranthesis do not match: %v\n", arg)
	panic("ident failed")
}

func isReturned(typ sys.Type, strace_arg string, return_vars *map[returnType]*Arg) *Arg {
	var val string
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
		Val: val,
	}
	if arg, ok := (*return_vars)[return_var]; ok {
		fmt.Println(return_var)
		return resultArg(typ, arg)
	}

	return nil
}

func addr(s *state, typ sys.Type, size uintptr, data *Arg) (*Arg, []*Call) {
	npages := (size + pageSize - 1) / pageSize
	if npages == 0 {
		npages = 1
	}
	for i := uintptr(0); i < maxPages-npages; i++ {
		free := true
		for j := uintptr(0); j < npages; j++ {
			if s.pages[i+j] {
				free = false
				break
			}
		}
		if !free {
			continue
		}

		/* mark memory as claimed */
		for j := uintptr(0); j < npages; j++ {
			s.pages[i+j] = true
		}
		// found a free memory section, let's mmap
		c := createMmapCall(i, npages)
		arg, calls := pointerArg(typ, i, 0, 0, data), []*Call{c}
		return arg, calls
	}
	panic("out of memory")
	//return r.randPageAddr(s, typ, npages, data, false), nil
}

func randPageAddr(s *state, typ sys.Type, npages uintptr, data *Arg, vma bool) *Arg {
	poolPtr := pageStartPool.Get().(*[]uintptr)
	starts := (*poolPtr)[:0]
	for i := uintptr(0); i < maxPages-npages; i++ {
		busy := true
		for j := uintptr(0); j < npages; j++ {
			if !s.pages[i+j] {
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
	var page uintptr
	if len(starts) != 0 {
		//page = starts[r.rand(len(starts))]
		page = starts[0]
	} else {
		page = uintptr(rand.Int63n(int64(maxPages - npages)))
	}
	if !vma {
		npages = 0
	}
	return pointerArg(typ, page, 0, npages, data)
}

// createMmapCall creates a "normal" mmap call that maps [start, start+npages) page range.
func createMmapCall(start, npages uintptr) *Call {
	meta := sys.CallMap["mmap"]
	mmap := &Call{
		Meta: meta,
		Args: []*Arg{
			pointerArg(meta.Args[0], start, 0, npages, nil),
			pageSizeArg(meta.Args[1], npages, 0),
			constArg(meta.Args[2], sys.PROT_READ|sys.PROT_WRITE),
			constArg(meta.Args[3], sys.MAP_ANONYMOUS|sys.MAP_PRIVATE|sys.MAP_FIXED),
			constArg(meta.Args[4], sys.InvalidFD),
			constArg(meta.Args[5], 0),
		},
		Ret: returnArg(meta.Ret),
	}
	return mmap
}

func getType(typ sys.Type) string {
	switch typ.(type) {
	case *sys.ResourceType:
		return "ResourceType"
	case *sys.BufferType:
		return "BufferType"
	case *sys.VmaType:
		return "VmaType"
	case *sys.FlagsType:
		return "FlagsType"
	case *sys.ConstType:
		return "ConstType"
	case *sys.IntType:
		return "IntType"
	case *sys.ProcType:
		return "ProcType"
	case *sys.ArrayType:
		return "ArrayType"
	case *sys.StructType:
		return "StructType"
	case *sys.UnionType:
		return "UnionType"
	case *sys.PtrType:
		return "PtrType"
	case *sys.LenType:
		return "LenType"
	case *sys.CsumType:
		return "CsumType"
	default:
		panic("unknown argument type")
	}
}

func parsePointerArg(p string) pointer {
	if p[0:int(math.Min(2,float64(len(p))))] == "0x" {
		return pointer{p, ""}
	}
	if p[0] != '&' {
		return pointer{"", p}
	}

	/* else pointer is in format &addr=val */
	s := strings.SplitN(p, "=", 2)
	addr, val := s[0], s[1]
	if addr[0] == '&' {
		return pointer{addr[1:],val}
	} else {
		return pointer{addr,val}
	}
}

func (p pointer) String() string {
	return fmt.Sprintf("&%v=%v", p.Addr, p.Val)
}

func readConsts(arch string) map[string]uint64 {
	constFiles, err := filepath.Glob("sys/*_" + arch + ".const")
	if err != nil {
		failf("failed to find const files: %v", err)
	}
	consts := make(map[string]uint64)
	for _, fname := range constFiles {
		f, err := os.Open(fname)
		if err != nil {
			failf("failed to open const file: %v", err)
		}
		defer f.Close()
		s := bufio.NewScanner(f)
		for s.Scan() {
			line := s.Text()
			if line == "" || line[0] == '#' {
				continue
			}
			eq := strings.IndexByte(line, '=')
			if eq == -1 {
				failf("malformed const file %v: no '=' in '%v'", fname, line)
			}
			name := strings.TrimSpace(line[:eq])
			val, err := strconv.ParseUint(strings.TrimSpace(line[eq+1:]), 0, 64)
			if err != nil {
				failf("malformed const file %v: bad value in '%v'", fname, line)
			}
			if old, ok := consts[name]; ok && old != val {
				failf("const %v has different values for %v: %v vs %v", name, arch, old, val)
			}
			consts[name] = val
		}
		if err := s.Err(); err != nil {
			failf("failed to read const file: %v", err)
		}
	}
	return consts
}

func failf(msg string, args ...interface{}) {
	fmt.Fprintf(os.Stderr, msg+"\n", args...)
	os.Exit(1)
}

func extractVal(flags string, consts *map[string]uint64) (uint64, error) {
	var val uint64 = 0
	for _, or_op := range strings.Split(flags, "|") {
		var and_val uint64  = 1 << 64 - 1
		for _, and_op := range strings.Split(or_op, "&") {
			c, ok := (*consts)[and_op]
			if !ok { // const doesn't exist, just return 0
				return 0, errors.New("constant not found: " + and_op)
			}
			and_val &= c
		}
		val |= and_val
	}
	return val, nil
}

/* State functions */
func newState() *state {
	s := &state{
		files:     make(map[string]bool),
		resources: make(map[string][]*Arg),
		strings:   make(map[string]bool),
	}
	return s
}

func (s *state) analyze(c *Call) {
	ForeachArgArray(&c.Args, c.Ret, func(arg, base *Arg, _ *[]*Arg) {
		switch typ := arg.Type.(type) {
		case *sys.ResourceType:
			if arg.Type.Dir() != sys.DirIn {
				s.resources[typ.Desc.Name] = append(s.resources[typ.Desc.Name], arg)
				// TODO: negative PIDs and add them as well (that's process groups).
			}
		case *sys.BufferType:
			if arg.Type.Dir() != sys.DirOut && arg.Kind == ArgData && len(arg.Data) != 0 {
				switch typ.Kind {
				case sys.BufferString:
					s.strings[string(arg.Data)] = true
				case sys.BufferFilename:
					s.files[string(arg.Data)] = true
				}
			}
		}
	})
	switch c.Meta.Name {
	case "mmap":
		// Filter out only very wrong arguments.
		length := c.Args[1]
		if length.AddrPage == 0 && length.AddrOffset == 0 {
			break
		}
		if flags, fd := c.Args[4], c.Args[3]; flags.Val&sys.MAP_ANONYMOUS == 0 && fd.Kind == ArgConst && fd.Val == sys.InvalidFD {
			break
		}
		s.addressable(c.Args[0], length, true)
	case "munmap":
		s.addressable(c.Args[0], c.Args[1], false)
	case "mremap":
		s.addressable(c.Args[4], c.Args[2], true)
	case "io_submit":
		if arr := c.Args[2].Res; arr != nil {
			for _, ptr := range arr.Inner {
				if ptr.Kind == ArgPointer {
					if ptr.Res != nil && ptr.Res.Type.Name() == "iocb" {
						s.resources["iocbptr"] = append(s.resources["iocbptr"], ptr)
					}
				}
			}
		}
	}
}

func (s *state) addressable(addr, size *Arg, ok bool) {
	if addr.Kind != ArgPointer || size.Kind != ArgPageSize {
		panic("mmap/munmap/mremap args are not pages")
	}
	n := size.AddrPage
	if size.AddrOffset != 0 {
		n++
	}
	if addr.AddrPage+n > uintptr(len(s.pages)) {
		panic(fmt.Sprintf("address is out of bounds: page=%v len=%v (%v, %v) bound=%v, addr: %+v, size: %+v",
			addr.AddrPage, n, size.AddrPage, size.AddrOffset, len(s.pages), addr, size))
	}
	for i := uintptr(0); i < n; i++ {
		s.pages[addr.AddrPage+i] = ok
	}
}


/* Arg helper functions */

func groupArg(t sys.Type, inner []*Arg) *Arg {
	return &Arg{Type: t, Kind: ArgGroup, Inner: inner}
}

func pointerArg(t sys.Type, page uintptr, off int, npages uintptr, obj *Arg) *Arg {
	return &Arg{Type: t, Kind: ArgPointer, AddrPage: page, AddrOffset: off, AddrPagesNum: npages, Res: obj}
}

func pageSizeArg(t sys.Type, npages uintptr, off int) *Arg {
	return &Arg{Type: t, Kind: ArgPageSize, AddrPage: npages, AddrOffset: off}
}

func constArg(t sys.Type, v uintptr) *Arg {
	return &Arg{Type: t, Kind: ArgConst, Val: v}
}

func dataArg(t sys.Type, data []byte) *Arg {
	return &Arg{Type: t, Kind: ArgData, Data: append([]byte{}, data...)}
}

func unionArg(t sys.Type, opt *Arg, typ sys.Type) *Arg {
	return &Arg{Type: t, Kind: ArgUnion, Option: opt, OptionType: typ}
}

func resultArg(t sys.Type, r *Arg) *Arg {
	arg := &Arg{Type: t, Kind: ArgResult, Res: r}
	if r.Uses == nil {
		r.Uses = make(map[*Arg]bool)
	}
	if r.Uses[arg] {
		panic("already used")
	}
	r.Uses[arg] = true
	return arg
}

func returnArg(t sys.Type) *Arg {
	if t != nil {
		return &Arg{Type: t, Kind: ArgReturn, Val: t.Default()}
	}
	return &Arg{Type: t, Kind: ArgReturn}
}

/* Misc Helpers */

func uintToVal(s string) (uint64, error) {
	var val uint64

	if strings.Contains(s, "*") {
		expression := strings.Split(s, "*")
		val = 1
		for _,v := range expression {
			v_parsed, ok := strconv.ParseInt(v, 0, 64)
			if ok != nil {
				failf("error evaluating expression %v\n", s)
			}
			val *= uint64(v_parsed)
		}
		return val, nil
	}
	if i,e := strconv.ParseInt(s, 0, 64); e == nil {
		return uint64(i), nil
	} else {
		return 0, e
	}
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
			fmt.Fprintf(os.Stderr, "fixing hash %v -> %v\n", key, sig)
			key = sig
		}
		db.Save(key, data, seq)
	}
	if err := db.Flush(); err != nil {
		failf("failed to save database file: %v", err)
	}
}
