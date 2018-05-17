package parser

import (
	"github.com/google/syzkaller/prog"
	"github.com/google/syzkaller/tools/moonshine/strace_types"
	"github.com/google/syzkaller/tools/moonshine/tracker"
	. "github.com/google/syzkaller/tools/moonshine/logging"
	"fmt"
	"math/rand"
)

type returnCache map[ResourceDescription]prog.Arg


func NewRCache() returnCache{
	return make(map[ResourceDescription]prog.Arg, 0)
}

func (r *returnCache) Cache(SyzType prog.Type, StraceType strace_types.Type, arg prog.Arg) {
	resDesc := ResourceDescription{
		Type: strace_types.GetSyzType(SyzType),
		Val: StraceType.String(),
	}
	(*r)[resDesc] = arg
}

func (r *returnCache) Get(SyzType prog.Type, StraceType strace_types.Type) prog.Arg{
	resDesc := ResourceDescription{
		Type: strace_types.GetSyzType(SyzType),
		Val: StraceType.String(),
	}
	if arg, ok := (*r)[resDesc]; ok {
		if arg != nil {
			return strace_types.ResultArg(SyzType, arg, SyzType.Default())
		}
	}

	return nil
}

type ResourceDescription struct {
	Type string
	Val string
}

type Context struct {
	Cache returnCache
	Prog *prog.Prog
	CurrentStraceCall *strace_types.Syscall
	CurrentSyzCall *prog.Call
	State *tracker.State
	Target *prog.Target
}

func NewContext(target *prog.Target) (ctx *Context) {
	ctx = &Context{}
	ctx.Cache = NewRCache()
	ctx.CurrentStraceCall = nil
	ctx.State = tracker.NewState(target)
	ctx.Target = target
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

func ParseProg(trace *strace_types.Trace, target *prog.Target) (*prog.Prog, *Context, error) {
	syzProg := new(prog.Prog)
	ctx := NewContext(target)
	ctx.Prog = syzProg
	for _, s_call := range trace.Calls {
		ctx.CurrentStraceCall = s_call
		if _, ok := strace_types.Unsupported[s_call.CallName]; ok {
			continue
		}
		ctx.CurrentStraceCall = s_call
		if call, err := parseCall(ctx); err == nil {
			syzProg.Calls = append(syzProg.Calls, call)
		} else {
			return nil, ctx, err
		}
	}
	return syzProg, ctx, nil
}

func parseCall(ctx *Context) (*prog.Call, error) {
	fmt.Printf("Parsing Call: %s\n", ctx.CurrentStraceCall.CallName)
	straceCall := ctx.CurrentStraceCall
	syzCallDef := ctx.Target.SyscallMap[straceCall.CallName]
	retCall := new(prog.Call)
	retCall.Meta = syzCallDef
	retCall.Ret = strace_types.ReturnArg(syzCallDef.Ret)
	ctx.CurrentSyzCall = retCall

	Preprocess(ctx)
	if call := ParseMemoryCall(ctx); call != nil {
		return call, nil
	}
	for i := range(straceCall.Args) {
		if arg, err := parseArgs(retCall.Meta.Args[i], straceCall.Args[i], ctx); err != nil {
			Failf("Failed to parse arg: %s\n", err.Error())
		} else {
			retCall.Args = append(retCall.Args, arg)
		}
		//arg := syzCall.Args[i]
	}
	parseResult(syzCallDef.Ret, straceCall.Ret, ctx)
	if len(syzCallDef.Args) != len(straceCall.Args) {
		fmt.Printf("syzkaller system call: " +
			"%s has %d arguments strace call: " +
			"%s has %d arguments",
			syzCallDef.CallName,
			len(syzCallDef.Args),
			straceCall.CallName,
			len(straceCall.Args))
	}
	return retCall, nil
}

func parseResult(syzType prog.Type, straceRet int64, ctx *Context) {
	if straceRet > 0 {
		//TODO: This is a hack NEED to refacto lexer to parser return values into strace types
		straceExpr := strace_types.NewExpression(strace_types.NewIntType(straceRet))
		switch syzType.(type) {
		case *prog.ResourceType:
			ctx.Cache.Cache(syzType, straceExpr, ctx.CurrentSyzCall.Ret)
		}
	}
}

func parseArgs(syzType prog.Type, straceArg strace_types.Type, ctx *Context) (prog.Arg, error) {
	switch a := syzType.(type) {
	case *prog.IntType, *prog.ConstType, *prog.FlagsType, *prog.LenType, *prog.ProcType, *prog.CsumType:
		return Parse_ConstType(a, straceArg, ctx)
	case *prog.ResourceType:
		return Parse_ResourceType(a, straceArg, ctx)
	case *prog.PtrType:
		return Parse_PtrType(a, straceArg, ctx)
	case *prog.BufferType:
		return Parse_BufferType(a, straceArg, ctx)
	case *prog.StructType:
		return Parse_StructType(a, straceArg, ctx)
	case *prog.ArrayType:
		return Parse_ArrayType(a, straceArg, ctx)
	case *prog.UnionType:
		return Parse_UnionType(a, straceArg, ctx)
	default:
		panic("Unsupported Type")
	}
}

func Parse_ArrayType(syzType *prog.ArrayType, straceType strace_types.Type, ctx *Context) (prog.Arg, error) {
	args := make([]prog.Arg, 0)
	switch a := straceType.(type) {
	case *strace_types.ArrayType:
		if syzType.Dir() == prog.DirOut {
			return GenDefaultArg(syzType, ctx), nil
		}
		for i := 0; i < a.Len; i++ {
			if arg, err := parseArgs(syzType.Type, a.Elems[i], ctx); err == nil {
				args = append(args, arg)
			} else {
				Failf("Error parsing array elem: %s\n", err.Error())
			}
		}
	default:
		Failf("Error parsing Array with Wrong Type: %v", straceType)
	}
	return strace_types.GroupArg(syzType, args), nil
}

func Parse_StructType(syzType *prog.StructType, straceType strace_types.Type, ctx *Context) (prog.Arg, error) {
	args := make([]prog.Arg, 0)
	switch a := straceType.(type) {
	case *strace_types.StructType:
		j := 0
		for i, _ := range(syzType.Fields) {
			if prog.IsPad(syzType.Fields[i]) {
				args = append(args, prog.DefaultArg(syzType.Fields[i]))
			} else {
				if j >= len(a.Fields) {
					args = append(args, GenDefaultArg(syzType.Fields[i], ctx))
				} else if arg, err := parseArgs(syzType.Fields[i], a.Fields[j], ctx); err == nil {
					args = append(args, arg)
				} else {
					Failf("Error parsing struct field: %#v", ctx)
				}
				j += 1
			}
		}
	case *strace_types.ArrayType:
		//Syzkaller's pipe definition expects a pipefd struct
		//But strace returns an array type
		for i, _ := range(syzType.Fields) {
			if arg, err := parseArgs(syzType.Fields[i], a.Elems[i], ctx); err == nil {
				args = append(args, arg)
			} else {
				Failf("Error parsing struct field: %#v", ctx)
			}
		}
	}
	return strace_types.GroupArg(syzType, args), nil
}

func Parse_UnionType(syzType *prog.UnionType, straceType strace_types.Type, ctx *Context) (prog.Arg, error) {
	idx := IdentifyUnionType(ctx)
	innerType := syzType.Fields[idx]
	if innerArg, err := parseArgs(innerType, straceType, ctx); err == nil {
		return strace_types.UnionArg(syzType, innerArg, innerType), nil
	} else {
		Failf("Error parsing union type: %#v", ctx)
	}
	return nil, nil
}

func IdentifyUnionType(ctx *Context) int {
	return 0
}

func Parse_BufferType(syzType *prog.BufferType, straceType strace_types.Type, ctx *Context) (prog.Arg, error) {
	fmt.Printf("Parsing Buffer Type\n")
	var arg prog.Arg
	if syzType.Dir() == prog.DirOut {
		switch syzType.Kind {
		case prog.BufferBlobRand:
			size := rand.Intn(256)
			arg = strace_types.DataArg(syzType, make([]byte, size))
		case prog.BufferBlobRange:
			max := rand.Intn(int(syzType.RangeEnd)-int(syzType.RangeBegin)+1)
			size := max + int(syzType.RangeBegin)
			arg = strace_types.DataArg(syzType, make([]byte, size))
		default:
			panic(fmt.Sprintf("unexpected buffer type. call %v arg %v", ctx.CurrentSyzCall, straceType))
		}
		return arg, nil
	}

	switch a := straceType.(type) {
	case *strace_types.BufferType:
		arg = strace_types.DataArg(syzType, []byte(a.Val))
		return arg, nil
	default:
		panic("Cannot parse type for Buffer Type")
	}
}

func Parse_PtrType(syzType *prog.PtrType, straceType strace_types.Type, ctx *Context) (prog.Arg, error) {
	fmt.Printf("Parsing Pointer Type\n")
	switch a := straceType.(type) {
	case *strace_types.PointerType:
		if a.IsNull() {
			return prog.DefaultArg(syzType), nil
		} else {
			if a.Res == nil {
				return GenDefaultArg(syzType.Type, ctx), nil
			}
			if res, err := parseArgs(syzType.Type, a.Res, ctx); err != nil {
				panic(fmt.Sprintf("Error parsing Ptr: %s", err.Error()))
			} else {
				return addr(ctx, syzType, res.Size(), res)
			}
		}
	default:
		if res, err := parseArgs(syzType.Type, a, ctx); err != nil {
			panic(fmt.Sprintf("Error parsing Ptr: %s", err.Error()))
		} else {
			return addr(ctx, syzType, res.Size(), res)
		}
	}
}

func Parse_ConstType(syzType prog.Type, straceType strace_types.Type, ctx *Context) (prog.Arg, error) {
	if syzType.Dir() == prog.DirOut {
		return prog.DefaultArg(syzType), nil
	}
	switch a := straceType.(type) {
	case *strace_types.Expression:
		return strace_types.ConstArg(syzType, a.Eval(ctx.Target)), nil
	case *strace_types.ArrayType:
		/*
		Sometimes strace represents a pointer to int as [0] which gets parsed
		as Array([0], len=1). A good example is ioctl(3, FIONBIO, [1]).
		 */
		if a.Len == 0 {
			panic(fmt.Sprintf("Parsing const type. Got array type with len 0: %#v", ctx))
		}
		return Parse_ConstType(syzType, a.Elems[0], ctx)
	default:
		panic("Unsupported Strace Type to Int Type")
	}
}

func Parse_ResourceType(syzType *prog.ResourceType, straceType strace_types.Type, ctx *Context) (prog.Arg, error) {
	if syzType.Dir() == prog.DirOut {
		res := strace_types.ResultArg(syzType, nil, syzType.Default())
		ctx.Cache.Cache(syzType, straceType, res)
		return res, nil
	}
	switch a := straceType.(type) {
	case *strace_types.Expression:
		val := a.Eval(ctx.Target)
		if arg := ctx.Cache.Get(syzType, straceType); arg != nil {
			return arg, nil
		}
		res := strace_types.ResultArg(syzType, nil, val)
		return res, nil
	default:
		panic("Resource Type only supports Expression")
	}
}


func GenDefaultArg(syzType prog.Type, ctx *Context) prog.Arg {
	switch a := syzType.(type) {
	case *prog.PtrType:
		res := GenDefaultArg(a.Type, ctx)
		ptr, _ := addr(ctx, syzType, res.Size(), res)
		return ptr
	case *prog.IntType, *prog.ConstType, *prog.FlagsType, *prog.LenType, *prog.ProcType, *prog.CsumType:
		return prog.DefaultArg(a)
	case *prog.BufferType:
		var arg prog.Arg
		switch a.Kind {
		case prog.BufferBlobRand:
			size := rand.Intn(256)
			arg = strace_types.DataArg(a, make([]byte, size))
		case prog.BufferBlobRange:
			max := rand.Intn(int(a.RangeEnd)-int(a.RangeBegin)+1)
			size := max + int(a.RangeBegin)
			arg = strace_types.DataArg(syzType, make([]byte, size))
		default:
			panic(fmt.Sprintf("unexpected buffer type. call %v", ctx.CurrentSyzCall))
		}
		return arg
	case *prog.StructType:
		var inner []prog.Arg
		for _, field := range a.Fields {
			inner = append(inner, GenDefaultArg(field, ctx))
		}
		return strace_types.GroupArg(a, inner)
	case *prog.UnionType:
		optType := a.Fields[0]
		return strace_types.UnionArg(a, GenDefaultArg(optType, ctx), optType)
	default:
		panic("Unsupported Type")
	}
}

func addr(ctx *Context, syzTyp prog.Type, size uint64, data prog.Arg) (prog.Arg, error) {
	fmt.Printf("Adding address of size: %d\n", size)
	arg := strace_types.PointerArg(syzTyp, uint64(0), 0, 0, data)
	ctx.State.Tracker.AddAllocation(ctx.CurrentSyzCall, size, arg)
	return arg, nil
}