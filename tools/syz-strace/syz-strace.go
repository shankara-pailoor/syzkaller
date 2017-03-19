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
)

var (
	unsupported = map[string]bool{
		"brk": true,
		"fstat": true,
    		"exit_group": true,
		"mprotect": true,
		"munmap": true,
		"execve": true,
		"access": true,
		"mmap": true,
		"arch_prctl": true, // has two conflicting method signatures!! http://man7.org/linux/man-pages/man2/arch_prctl.2.html
		"rt_sigaction": true, // constants such as SIGRTMIN are not defined in syzkaller, and missing last void __user *, restorer argument
		"rt_sigprocmask": true, // second arg given as an array, should be pointer
		"getrlimit": true, // has arg 8192*1024, cannot evaluate easily
		"statfs": true, // types disagree, strace gives struct, syzkaller expects buffer
		"fstatfs": true, // types disagree, strace gives struct, syzkaller expects buffer
		"ioctl": true, // types disagree, strace gives struct, syzkaller expects buffer
		"getdents": true, // types disagree, strace gives struct, syzkaller expects buffer
	}
)

const (
	munmap = "munmap"
	arch = "amd64"
	maxLineLen       = 256 << 10
	pageSize   = 4 << 10
	maxPages = 4 << 10
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

func main() {
	prog :=  new(Prog)
	p := sparser.NewParser(os.Stdin)
	return_vars := make(map[returnType]*Arg)
	consts := readConsts(arch)
	s := newState() // to keep track of resources and memory

	// loop until we've entered the real program by seeing munmap
	/* for {
		line, err := p.Parse()
		if err != nil {
			fmt.Errorf("Line: %s\n", err.Error())
		}

		if line.FuncName == munmap {
			break
		}
	} */

	for {
		line, err := p.Parse()
		if err != nil {
			if err != sparser.ErrEOF {
				fmt.Println(err.Error())
			}
			break
		}

		if _, ok := unsupported[line.FuncName]; ok {
			continue // don't parse unsupported syscalls
		}

		meta := sys.CallMap[line.FuncName]
		if meta == nil {
			fmt.Printf("unknown syscall %v\n", line.FuncName)
			break
		}

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
			if i >= len(meta.Args) {
				fmt.Errorf("wrong call arg count: %v, want %v", i+1, len(meta.Args))
			}
			if (i < len(line.Args)) {
				strace_arg = line.Args[i]
			} else {
				strace_arg = "nil"
			}

			parsedArg, calls1 := parseArg(typ, strace_arg, &consts, &return_vars, line.FuncName, s)
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
			return_vars[return_var] = c.Ret
		}

		// add calls to our program
		for _,c := range calls {
			// TODO: sanitize c?
			s.analyze(c)
			prog.Calls = append(prog.Calls, c)
		}

		fmt.Println("---------done parsing line--------\n")
	}
	if err := prog.Validate(); err != nil {
		fmt.Println("ERROR: %v", err.Error())
		return
	}

	fmt.Println("success!")
	fmt.Println("Serializing program of length", len(prog.Calls))

	os.Mkdir("serialized", 0750)

	if err := ioutil.WriteFile("serialized/serialized.txt", prog.Serialize(), 0640); err != nil {
		failf("failed to output file: %v", err)
	}
	fmt.Println("serialized output to serialized.txt")

	fmt.Println("packing into corpus.db")
	pack("serialized", "corpus.db")
	return
}



func parseArg(typ sys.Type, strace_arg string,
	      consts *map[string]uint64, return_vars *map[returnType]*Arg,
              call string, s *state) (arg *Arg, calls []*Call) {

	fmt.Printf("-----Entering parseArg-------" +
		"\nparsing arg: %v" +
		"\nfor call: %v \n", strace_arg, call)
	// check if this is a return arg
	if arg := isReturned(typ, strace_arg, return_vars); arg != nil {
		fmt.Println("Discovered return type!")
		fmt.Println("-------exiting parseArg--------\n")
		return arg, nil
	}

	switch a := typ.(type) {
	case *sys.FlagsType:
		fmt.Println("FlagsType")
		arg, calls = constArg(a, uintptr(extractVal(strace_arg, consts))), nil
	case *sys.ResourceType:
		fmt.Println("Resource Type: %v", a.Desc)
		// TODO: special parsing required if struct is type timespec or timeval
		extracted_int, err := strconv.ParseUint(strace_arg, 0, 64)
		if err != nil {
			failf("Error converting int type for syscall: %s, %s", call, err.Error())
		}
		// TODO: special values only
		arg, calls = constArg(a, uintptr(extracted_int)), nil
	case *sys.BufferType:
		fmt.Println("Buffer Type")
		fmt.Println(strace_arg)
		if strace_arg[0] != '"' || strace_arg[len(strace_arg)-1] != '"' {
			panic("unexpected buffer type, not a string")
		}

		if a.Dir() != sys.DirOut {
			arg = dataArg(a, []byte(strace_arg[1:len(strace_arg)-1]))
		} else {
			arg = dataArg(a, make([]byte, len(strace_arg)-2)) // -2 for the " "
		}
		return arg, nil
	case *sys.PtrType:
		fmt.Printf("Pointer with inner type: %v Call: %s\n", a.Type, call)
		ptr := parsePointerArg(strace_arg)
		if ptr.Val == "" {
			ptr.Val = "nil" // TODO: this is really bad, consider refactoring parseArg
		}

		inner_arg, inner_calls := parseArg(a.Type, ptr.Val, consts, return_vars, call, s)

		/* cache this pointer value */
		switch a.Type.(type) {
		/* don't cache for these types */
		case *sys.PtrType, *sys.ArrayType, *sys.StructType:
		default:
			return_var := returnType{
				getType(a.Type),
				ptr.Val,
			}
			(*return_vars)[return_var] = inner_arg
		}

		outer_arg, outer_calls := addr(s, a, inner_arg.Size(), inner_arg)
		inner_calls = append(inner_calls, outer_calls...)
		arg, calls = outer_arg, inner_calls
	case *sys.IntType:
		fmt.Println("IntType")
		var extracted_int uint64
		var err error = nil
		if strace_arg == "nil" {
			extracted_int = uint64(a.Default())
		} else {
			extracted_int, err = strconv.ParseUint(strace_arg, 0, 64)
		}
		if err != nil {
			extracted_int = extractVal(strace_arg, consts) // maybe a flag?
			//failf("Error converting int type for syscall: %s, %s", call, err.Error())
		}
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
	case *sys.ConstType, *sys.ProcType, *sys.LenType, *sys.CsumType:
		fmt.Println("Const/Proc/Len/Csum Type")
		return constArg(a, toVal(strace_arg)), nil
	case *sys.ArrayType:
		// clip the square brackets
		strace_arg = strace_arg[1:len(strace_arg)-1]
		fmt.Printf("ArrayType %v\n", a.TypeName)
		var args []*Arg
		for len(strace_arg) > 0 {
			param, rem := ident(strace_arg)
			strace_arg = rem
			inner_arg, inner_calls := parseArg(a.Type, param, consts, return_vars, call, s)
			args = append(args, inner_arg)
			calls = append(calls, inner_calls...)
		}
		arg = groupArg(typ, args)
	case *sys.StructType:
		name, val := "nil", "nil"
		is_nil := (strace_arg == "nil")
		// clip the curly brackets
		strace_arg = strace_arg[1:len(strace_arg) - 1]
		fmt.Printf("StructType %v", a.TypeName)
		struct_args := strings.Split(strace_arg, ", ")
		args := make([]*Arg, 0)
		for i, arg_type := range a.Fields {
			if !is_nil { // if nil, we need to generate nil values for entire struct
				struct_arg := struct_args[i]
				param := strings.SplitN(struct_arg, "=", 2)
				name, val = param[0], param[1]
			}

			fmt.Printf("generating arg (%v) for struct type %v, field: %v\n", i, a.Name(), name)
			inner_arg, inner_calls := parseArg(arg_type, val, consts, return_vars, call, s)

			/* cache this pointer value */
			if val != "nil" {
				return_var := returnType{
					getType(arg_type),
					val,
				}
				(*return_vars)[return_var] = inner_arg
			}

			args = append(args, inner_arg)
			calls = append(calls, inner_calls...)
		}
		arg = groupArg(a, args)
		return arg, calls
	default:
		fmt.Printf("Call: %s Arg: %v\n", call, typ)
		fmt.Printf("Args: %v\n", reflect.TypeOf(typ))
		panic("uncaught type")
	}

	fmt.Println("-------exiting parseArg--------")

	return arg, calls
}

/* func parseInnerArgs(typ sys.Type, strace_arg string,
	consts *map[string]uint64, return_vars *map[returnType]*Arg,
	call string, s *state) (arg []*Arg, calls []*Call, tokens []string) {
} */


func ident(arg string) (string, string) {
	fmt.Printf("ident parsing arg %v\n", arg)
	s := make(Stack, 0)
	var r byte
	for i := 0; i < len(arg); i++ {
		// skip whitespace and commas
		for i < len(arg) && (arg[i] == ' ' || arg[i] == '\t' || arg[i] == ',') {
			i++
		}

		j := i

		for ; ((arg[i] != ',' && i != len(arg)) || len(s) != 0); i++ {
			if arg[i] == '[' || arg[i] == '{' {
				s = s.Push(arg[i])
				continue
			}
			if arg[i] == ']' {
				s, r = s.Pop()
				if r != '[' {
					fmt.Println(arg)
					panic("invalid argument syntax")
				}
				continue
			}
			if arg[i] == '}' {
				s, r = s.Pop()
				if r != '{' {
					fmt.Println(arg)
					panic("invalid argument syntax")
				}
				continue
			}
		}
		fmt.Printf("ident returning %v : %v\n", arg[j:i], arg[i:])
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
	if p[0] == '0' {
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

func extractVal(flags string, consts *map[string]uint64) uint64{
	var val uint64 = 0
	for _, or_op := range strings.Split(flags, "|") {
		var and_val uint64  = 1 << 64 - 1
		for _, and_op := range strings.Split(or_op, "&") {
			and_val &= (*consts)[and_op]
		}
		val |= and_val
	}
	return val
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

func toVal(s string) uintptr {
	if i,e := strconv.ParseUint(s, 0, 64); e == nil {
		return uintptr(i)
	} else {
		fmt.Println(e)
		panic("invalid return format")
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
