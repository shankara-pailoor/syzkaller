package parser

import (
	"github.com/google/syzkaller/tools/moonshine/strace_types"
	"github.com/google/syzkaller/prog"
	. "github.com/google/syzkaller/tools/moonshine/logging"
)

func ParseInnerCall(syzType prog.Type, straceType *strace_types.Call, ctx *Context) prog.Arg {
	switch straceType.CallName {
	case "htons":
		return parse_Htons(syzType, straceType, ctx)
	case "inet_addr":
		return parse_InetAddr(syzType, straceType, ctx)
	default:
		Failf("Inner Call: %s Unsupported", straceType.CallName)
	}
	return nil
}

func parse_Htons(syzType prog.Type, straceType *strace_types.Call, ctx *Context) prog.Arg {
	if len(straceType.Args) > 1 {
		panic("Parsing Htons...it has more than one arg.")
	}
	procType := syzType.(*prog.ProcType)
	switch a := straceType.Args[0].(type) {
	case *strace_types.Expression:
		val := a.Eval(ctx.Target)
		if val >= procType.ValuesPerProc {
			return strace_types.ConstArg(syzType, procType.ValuesPerProc-1)
		} else {
			return strace_types.ConstArg(syzType, val)
		}
		return prog.MakeConstArg(syzType, val)
	default:
		panic("First arg of Htons is not expression")
	}
}

func parse_InetAddr(syzType prog.Type, straceType *strace_types.Call, ctx *Context) prog.Arg {
	unionType := syzType.(*prog.UnionType)
	var optType prog.Type
	var inner_arg prog.Arg
	if len(straceType.Args) > 1 {
		panic("Parsing InetAddr...it has more than one arg.")
	}
	switch a := straceType.Args[0].(type) {
	case *strace_types.Ipv4Type:
		switch a.Str {
		case "0.0.0.0":
			optType = unionType.Fields[0]
		case "127.0.0.1":
			optType = unionType.Fields[3]
		case "255.255.255.255":
			optType = unionType.Fields[6]
		default:
			optType = unionType.Fields[7]
		}
		inner_arg = prog.DefaultArg(optType)
	default:
		panic("Parsing inet_addr and inner arg has non ipv4 type")
	}
	return strace_types.UnionArg(syzType, inner_arg, optType)
}