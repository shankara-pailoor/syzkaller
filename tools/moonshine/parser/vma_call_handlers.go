package parser

import (
	"fmt"
	"github.com/google/syzkaller/prog"
	"github.com/google/syzkaller/tools/moonshine/strace_types"
	"github.com/google/syzkaller/tools/moonshine/tracker"
)

const (
	pageSize = 4096
	MapFixed = "MAP_FIXED"
)

func ParseMemoryCall(ctx *Context) *prog.Call {
	syzCall := ctx.CurrentSyzCall
	straceCall := ctx.CurrentStraceCall
	if straceCall.CallName == "mmap" {
		return ParseMmap(syzCall.Meta, straceCall, ctx)
	} else if straceCall.CallName == "msync" {
		return ParseMsync(syzCall.Meta, straceCall, ctx)
	} else if straceCall.CallName == "mprotect" {
		return ParseMprotect(syzCall.Meta, straceCall, ctx)
	} else if straceCall.CallName == "munmap" {
		return ParseMunmap(syzCall.Meta, straceCall, ctx)
	}
	return nil
}

func ParseMmap(mmap *prog.Syscall, syscall *strace_types.Syscall, ctx *Context) *prog.Call {
	call := &prog.Call{
		Meta: mmap,
		Ret: strace_types.ReturnArg(mmap.Ret),
	}
	fmt.Printf("Call: %v\n", call)
	length := uint64(0)

	length = ParseLength(syscall.Args[1], ctx)
	length = (length/pageSize + 1)*pageSize

	addrArg, start := ParseAddr(length, mmap.Args[0], syscall.Args[0], ctx)
	lengthArg := prog.MakeConstArg(mmap.Args[1], length)
	protArg := ParseFlags(mmap.Args[2], syscall.Args[2], ctx, false)
	flagArg := ParseFlags(mmap.Args[3], syscall.Args[3], ctx, true)
	fdArg := ParseFd(mmap.Args[4], syscall.Args[4], ctx)

	call.Args = []prog.Arg {
		addrArg,
		lengthArg,
		protArg,
		flagArg,
		fdArg,
		prog.MakeConstArg(mmap.Args[5], 0),
	}
	ctx.State.Tracker.CreateMapping(call, len(ctx.Prog.Calls), call.Args[0], start, start+length) //All mmaps have fixed mappings in syzkaller
	return call
}

func ParseMsync(msync *prog.Syscall, syscall *strace_types.Syscall, ctx *Context) *prog.Call {
	fmt.Printf("MSYNC PARSING\n")
	call := &prog.Call{
		Meta: msync,
		Ret: strace_types.ReturnArg(msync.Ret),
	}

	addrArg, address := ParseAddr(1, msync.Args[0], syscall.Args[0], ctx)
	length := uint64(0)
	length = ParseLength(syscall.Args[1], ctx)
	lengthArg := prog.MakeConstArg(msync.Args[1], length)
	protArg := ParseFlags(msync.Args[2], syscall.Args[2], ctx, false)
	AddDependency(address, length, addrArg, ctx)
	call.Args = []prog.Arg {
		addrArg,
		lengthArg,
		protArg,
	}
	return call
}

func ParseMprotect(mprotect *prog.Syscall, syscall *strace_types.Syscall, ctx *Context) *prog.Call {
	call := &prog.Call {
		Meta: mprotect,
		Ret: strace_types.ReturnArg(mprotect.Ret),
	}

	addrArg, address := ParseAddr(pageSize, mprotect.Args[0], syscall.Args[0], ctx)
	length := ParseLength(syscall.Args[1], ctx)
	fmt.Printf("MProtect Length: %d\n", length)
	lengthArg := prog.MakeConstArg(mprotect.Args[1], length)
	protArg := ParseFlags(mprotect.Args[2], syscall.Args[2], ctx, false)
	AddDependency(address, length, addrArg, ctx)
	call.Args = []prog.Arg {
		addrArg,
		lengthArg,
		protArg,
	}
	return call
}

func ParseMunmap(munmap *prog.Syscall, syscall *strace_types.Syscall, ctx *Context) *prog.Call {
	call := &prog.Call {
		Meta: munmap,
		Ret: strace_types.ReturnArg(munmap.Ret),
	}
	_, address := ParseAddr(pageSize, munmap.Args[0], syscall.Args[0], ctx)
	addrArg := prog.MakePointerArg(munmap.Args[0], address/pageSize, 0, 1, nil)
	length := ParseLength(syscall.Args[1], ctx)
	lengthArg := prog.MakeConstArg(munmap.Args[1], length)
	AddDependency(address, length, addrArg, ctx)
	call.Args = []prog.Arg{
		addrArg,
		lengthArg,
	}
	fmt.Printf("Finished parsing Munmap\n")
	return call
}


func ParseAddr(length uint64, syzType prog.Type, straceType strace_types.Type,  ctx *Context) (prog.Arg, uint64){
	switch a := straceType.(type) {
	case *strace_types.PointerType:
		var addrStart uint64
		if a.IsNull() {
			//Anonymous MMAP
			addrStart = uint64(ctx.CurrentStraceCall.Ret)
			return prog.MakePointerArg(syzType, addrStart, 0, length/pageSize, nil), addrStart
		} else {
			return prog.MakePointerArg(syzType, a.Address, 0, length/pageSize, nil), a.Address
		}
	case *strace_types.Expression:
		addrStart := a.Eval(ctx.Target)
		return prog.MakePointerArg(syzType, addrStart, 0, length/pageSize, nil), addrStart
	default:
		panic("Failed to parse mmap")
	}
}

func AddDependency(start, length uint64, addr prog.Arg, ctx *Context) {
	if mapping := ctx.State.Tracker.FindLatestOverlappingVMA(start); mapping != nil {
		fmt.Printf("Found mapping: %v\n", mapping)

		dep := tracker.NewMemDependency(len(ctx.Prog.Calls), addr, start, start+length)
		mapping.AddDependency(dep)
	}

}

func ParseLength(straceType strace_types.Type, ctx *Context) uint64 {
	switch a := straceType.(type) {
	case *strace_types.Expression:
		return a.Eval(ctx.Target)
	default:
		panic("Parsing Mmap length but type is not expression")
	}
}

func ParseFlags(syzType prog.Type, straceType strace_types.Type, ctx *Context, mapFlag bool) prog.Arg {
	switch a := straceType.(type) {
	case *strace_types.Expression:
		if mapFlag {
			val := a.Eval(ctx.Target) | ctx.Target.ConstMap[MapFixed]
			return prog.MakeConstArg(syzType, val)
		} else {
			return prog.MakeConstArg(syzType, a.Eval(ctx.Target))
		}
	default:
		panic("Parsing Flags")
	}
}

func ParseFd(syzType prog.Type, straceType strace_types.Type, ctx *Context) prog.Arg {
	if arg := ctx.Cache.Get(syzType, straceType); arg != nil {
		return prog.MakeResultArg(arg.Type(), arg, arg.Type().Default())
	}
	switch a := straceType.(type) {
	case *strace_types.Expression:
		return prog.MakeResultArg(syzType, nil, a.Eval(ctx.Target))
	default:
		panic("Failed to Parse Fd because type is not Expression")
	}
}
