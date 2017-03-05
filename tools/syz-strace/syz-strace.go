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
	"bytes"
	"reflect"
)

var (
	entered = false
	unsupported = map[string]bool{
		"brk": true,
		"fstat": true,
	}
)

const (
	munmap = "munmap"
	arch = "amd64"
	maxLineLen       = 256 << 10
	pageSize   = 4 << 10
	maxPages = 4 << 10
)


type pointer struct {
	Addr	string
	Val	string
}

type parser struct {
	r *bufio.Scanner
	s string
	i int
	l int
	e error
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

func main() {
	prog :=  new(Prog)
	p := sparser.NewParser(os.Stdin)
	return_vars := make(map[returnType]*Arg)
	consts := readConsts(arch)
	s := newState() // to keep track of resources and memory

	// loop until we've entered the real program by seeing munmap
	for {
		line, err := p.Parse()
		if err != nil {
			fmt.Errorf("Line: %s\n", err.Error())
		}

		if line.FuncName == munmap {
			break
		}
	}

	for {
		line, err := p.Parse()
		if err != nil {
			fmt.Errorf("Line: %s\n", err.Error())
		}
		if _, ok := unsupported[line.FuncName]; ok {
			continue // don't parse unsupported syscalls
		}

		meta := sys.CallMap[line.FuncName]
		if meta == nil {
			fmt.Errorf("unknown syscall %v", line.FuncName)
		}

		c := &Call{
			Meta: meta,
			Ret:  returnArg(meta.Ret, line.Result),
		}
		var calls []*Call

		for i, strace_arg := range line.Args {
			if i >= len(meta.Args) {
				fmt.Errorf("wrong call arg count: %v, want %v", i+1, len(meta.Args))
			}
			typ := meta.Args[i]
			parsedArg, calls1 := parseArg(typ, strace_arg, &consts, &return_vars, line.FuncName, s)
			c.Args = append(c.Args, parsedArg)
			calls = append(calls, calls1...)
		}

		calls = append(calls, c)
		prog.Calls = append(prog.Calls, calls)
		return_var := returnType{
			getType(meta.Ret),
			line.Result,
		}
		return_vars[return_var] = c.Ret

		//fmt.Printf("Signal: %v\n", line.Signal)
		//fmt.Printf("FuncName: %v\n", line.FuncName)
		//fmt.Printf("Args: %v\n", line.Args)
		//for j, arg := range line.Args {
		//	fmt.Printf("\narg %v: %v\n", j, arg)
		//}
		//fmt.Printf("Result: %v\n", line.Result)
	}
	if err := prog.Validate(); err != nil {
		fmt.Errorf(err)
	}

	//TODO: serialize and put in corpus

	//fmt.Printf("--------------\n\n\n\n---------")
	//fmt.Printf("%v\n", len(sys.CallMap))
	//for k,v := range sys.CallMap {
	//	fmt.Printf("%v: %v\n", k, v)
	//}
}



func parseArg(typ sys.Type, strace_arg string,
	      consts *map[string]uint64, return_vars *map[returnType]*Arg,
              call string, s *state) (arg *Arg, calls []*Call) {

	// check if this is a return arg
	if arg := isReturned(typ, strace_arg, return_vars); arg != nil {
		return arg, nil
	}

	switch a := typ.(type) {
	case *sys.FlagsType:
		arg, calls = constArg(a, uintptr(extractVal(strace_arg, consts))), nil
	case *sys.ResourceType:
		fmt.Printf("Resource Type: %v Argument: %s\n", a.Desc, strace_arg)
		extracted_int, err := strconv.ParseInt(strace_arg, 10, 64)
		if err != nil {
			failf("Error converting int type for syscall: %s, %s", call, err.Error())
		}
		arg, calls = constArg(a, uintptr(extracted_int)), nil
	case *sys.BufferType:
		// check if its a pointer or raw string
		fmt.Printf("Buffer Type: %v Call: %s\n", strace_arg, call)
		arg, calls = dataArg(a, []byte(strace_arg)), nil
	case *sys.PtrType:
		fmt.Printf("Pointer: %v inner type: %v Call: %s\n", strace_arg, a.Type, call)
		ptr := parsePointerArg(strace_arg)
		inner_arg, inner_calls := parseArg(a.Type, ptr.Val, consts, return_vars, call, s)
		outer_arg, outer_calls := addr(s, a, inner_arg.Size(), inner_arg)
		inner_calls = append(inner_calls, outer_calls)
		arg, calls = outer_arg, inner_calls
	case *sys.IntType:
		extracted_int, err := strconv.ParseInt(strace_arg, 10, 64)
		if err != nil {
			failf("Error converting int type for syscall: %s, %s", call, err.Error())
		}
		arg, calls = constArg(a, uintptr(extracted_int)), nil
	case *sys.VmaType:
		fmt.Printf("VMA Type: %v Call: %s\n", strace_arg, call)
		// TODO: this should be covered by a previous mmap
		arg, calls = &Arg{Type: a, Val: uintptr(1), Kind: ArgPointer}, nil
	case *sys.ConstType, *sys.ProcType, *sys.LenType, *sys.CsumType:
		fmt.Printf("Const/Proc/Len/Csum Type: %v Call: %s\n", strace_arg, call)
		return constArg(a, uintptr(strace_arg)), nil
	case *sys.ArrayType:
		// TODO: implement
		panic("not implemented")
	case *sys.StructType:
		// TODO: implement
		//inner_args, inner_calls, tokens := parseInnerArgs(a, strace_arg, consts, return_vars, call, s)
		// add inner args to return map
		for i,inner_arg := range inner_args {
			return_var := returnType{getType(inner_arg.Type),tokens[i]}
			return_vars[return_var] = inner_arg
		}


	default:
		fmt.Printf("Call: %s Arg: %v\n", call, typ)
		fmt.Printf("Args: %v\n", reflect.TypeOf(typ))
		panic("uncaught type")
	}

	// insert arg into returned map in case it is used elsewhere
	return_var := returnType{
		getType(typ),
		strace_arg,
	}
	return_vars[return_var] = arg

	return arg, calls
}

func parseInnerArgs(typ sys.Type, strace_arg string,
	consts *map[string]uint64, return_vars *map[returnType]*Arg,
	call string, s *state) (arg []*Arg, calls []*Call, tokens []string) {

	p := &parser{r: bufio.NewScanner(bytes.NewReader(strace_arg))}
	p.r.Buffer(nil, maxLineLen)

	// TODO: parse internal args, recursively build out

}




func isReturned(typ sys.Type, strace_arg string, return_vars *map[returnType]*Arg) *Arg {
	var val string
	if strace_arg[0] == '&' {
		val = parsePointerArg(strace_arg).Addr
	} else {
		val = strace_arg
	}
	return_var := returnType{
		Type: getType(typ),
		Val: val,
	}
	if arg,ok := return_vars[return_var]; ok {
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
		// found a free memory section, let's mmap
		c := createMmapCall(i, npages)
		return pointerArg(typ, i, 0, 0, data), []*Call{c}
	}
	panic("out of memory")
	//return r.randPageAddr(s, typ, npages, data, false), nil
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
		Ret: returnArg(meta.Ret, string(meta.Ret.Default())),
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
	s := strings.Split(p, "=")
	addr, val := s[0], s[1]
	if addr[0] == '&' {
		return pointer{addr[1:],val}
	} else {
		return pointer{addr,val}
	}
}

func (p pointer) String() string {
	return fmt.Sprintf("%v:=%v", p.Addr, p.Val)
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

func extractVal(flags string, consts map[string]uint64) uint64{
	var val uint64 = 0
	for _, or_op := range strings.Split(flags, "|") {
		var and_val uint64  = 1 << 64 - 1
		for _, and_op := range strings.Split(or_op, "&") {
			and_val &= consts[and_op]
		}
		val |= and_val
	}
	return val
}

func newState() *state {
	s := &state{
		files:     make(map[string]bool),
		resources: make(map[string][]*Arg),
		strings:   make(map[string]bool),
	}
	return s
}

/* Arg helper functions */

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

func returnArg(t sys.Type, val string) *Arg {
	if t != nil {
		return &Arg{Type: t, Kind: ArgReturn, Val: uintptr(val)}
	}
	return &Arg{Type: t, Kind: ArgReturn}
}