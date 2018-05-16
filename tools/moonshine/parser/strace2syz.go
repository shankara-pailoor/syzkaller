package parser

import (
	"github.com/google/syzkaller/prog"
	"github.com/google/syzkaller/tools/moonshine/strace_types"
	"github.com/google/syzkaller/tools/moonshine/tracker"
	"fmt"
)

type TypePair struct {
	straceType string
	syzType string
}

type returnCache map[ResourceDescription]prog.Arg

func NewRCache() returnCache{
	return make(map[ResourceDescription]prog.Arg, 0)
}

type ResourceDescription struct {
	Type string
	Val string
}

type Context struct {
	cache returnCache
	currentStraceCall *strace_types.Syscall
	state *tracker.State
	target *prog.Target
}

func NewContext(target *prog.Target) (ctx *Context) {
	ctx = &Context{}
	ctx.cache = NewRCache()
	ctx.currentStraceCall = nil
	ctx.state = tracker.NewState(target)
	ctx.target = target
	return
}

type ArgParseHandler func(strace_types.Type, prog.Type, *Context) (prog.Arg, error)


/*
func parseCall(ctx *Context) (*prog.Call, error) {
	straceCall := ctx.currentStraceCall
	callMeta := ctx.target.SyscallMap[straceCall.CallName]
	var straceArg strace_types.Type
	for i, argTyp := range callMeta.Args {
		straceArg = straceCall.Args[i]

	}
}*/

func ParseProg(trace *strace_types.Trace, target *prog.Target) (*prog.Prog, error) {
	syzProg := new(prog.Prog)
	ctx := NewContext(target)
	for _, s_call := range trace.Calls {
		if _, ok := strace_types.Unsupported[s_call.CallName]; ok {
			continue
		}
		ctx.currentStraceCall = s_call
		if call, err := parseCall(ctx); err == nil {
			syzProg.Calls = append(syzProg.Calls, call)
		} else {
			return nil, err
		}
	}
	return syzProg, nil
}

func parseCall(ctx *Context) (*prog.Call, error) {
	straceCall := ctx.currentStraceCall
	syzCall := ctx.target.SyscallMap[straceCall.CallName]
	for i := range(straceCall.Args) {
		switch a := straceCall.Args[i].(type) {
		case *strace_types.Expression:
			fmt.Printf("call: %s, EvalString: %s, Eval: %d\n",
				straceCall.CallName,
				a.String(),
				a.Eval(ctx.target))
		default:
			break
		}
		//arg := syzCall.Args[i]
	}
	if len(syzCall.Args) != len(straceCall.Args) {
		fmt.Printf("syzkaller system call: " +
			"%s has %d arguments strace call: " +
			"%s has %d arguments",
			syzCall.CallName,
			len(syzCall.Args),
			straceCall.CallName,
			len(straceCall.Args))
	}
	return nil, nil
}

func parseArgs(syzArg *prog.Arg, straceArg *strace_types.Type, ctx *Context) (*prog.Arg, error) {
	switch a := syzArg.(type) {
	case *prog.FlagsType:
		return Parse_FlagType(a, straceArg, ctx)
	case *prog.ResourceType:
		return Parse_ResourceType(a, straceArg, ctx)
	case *prog.IntType:
		return Parse_IntType(a, straceArg, ctx)
	case *prog.PtrType:

	default:
		panic("Unsupported Type")
	}
}

func Parse_PtrType(syzType *prog.PtrType, straceType strace_types.Type, ctx *Context) (prog.Arg, error) {
	switch a := straceType.(type) {
	case *strace_types.PointerType:
		if a.IsNull() {
			return prog.DefaultArg(syzType), nil
		} else {

		}
	}
}

func Parse_IntType(syzType *prog.IntType, straceType strace_types.Type, ctx *Context) (prog.Arg, error) {
	switch a := straceType.(type) {
	case *strace_types.Expression:
		return strace_types.ConstArg(syzType, a.Eval(ctx.target)), nil
	default:
		panic("Unsupported Strace Type to Int Type")
	}
}

func Parse_ResourceType(syzType *prog.ResourceType, straceType strace_types.Type, ctx *Context) (prog.Arg, error) {
	switch a := straceType.(type) {
	case *strace_types.Expression:
		if syzType.Dir() == prog.DirOut {
			return strace_types.ResultArg(a, nil, syzType.Default()), nil
		}
		return strace_types.ResultArg(syzType, nil, a.Eval(ctx.target)), nil
	default:
		panic("Resource Type only supports Expression")
	}
}

func Parse_FlagType(syzType *prog.FlagsType, straceType strace_types.Type, ctx *Context) (prog.Arg, error) {
	switch a := straceType.(type) {
	case *strace_types.Expression:
		return strace_types.ConstArg(syzType, a.Eval(ctx.target)), nil
	default:
		panic("Flag type only supports Expression")
	}
}
