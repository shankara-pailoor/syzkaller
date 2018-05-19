package parser

import (
	"github.com/google/syzkaller/prog"
	"github.com/google/syzkaller/tools/moonshine/strace_types"
	"github.com/google/syzkaller/tools/moonshine/tracker"
	. "github.com/google/syzkaller/tools/moonshine/logging"
	"fmt"
	"math/rand"
	"encoding/binary"
)

type returnCache map[ResourceDescription]prog.Arg


func NewRCache() returnCache{
	return make(map[ResourceDescription]prog.Arg, 0)
}

func (r *returnCache) Cache(SyzType prog.Type, StraceType strace_types.Type, arg prog.Arg) {
	fmt.Printf("Caching Val: %s\n", StraceType.String())
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
	fmt.Printf("Getting cache value with str: %s\n", StraceType.String())
	if arg, ok := (*r)[resDesc]; ok {
		if arg != nil {
			fmt.Printf("Hit cache value\n")
			return arg
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


func ParseProg(trace *strace_types.Trace, target *prog.Target) (*prog.Prog, *Context, error) {
	syzProg := new(prog.Prog)
	ctx := NewContext(target)
	ctx.Prog = syzProg
	for _, s_call := range trace.Calls {
		ctx.CurrentStraceCall = s_call
		if _, ok := strace_types.Unsupported[s_call.CallName]; ok {
			continue
		}
		if s_call.Paused {
			/*Probably a case where the call was killed by a signal like the following
			2179  wait4(2180,  <unfinished ...>
			2179  <... wait4 resumed> 0x7fff28981bf8, 0, NULL) = ? ERESTARTSYS
			2179  --- SIGUSR1 {si_signo=SIGUSR1, si_code=SI_USER, si_pid=2180, si_uid=0} ---
			*/
			continue
		}
		ctx.CurrentStraceCall = s_call
		if call, err := parseCall(ctx); err == nil {
			if call == nil {
				continue
			}
			syzProg.Calls = append(syzProg.Calls, call)
		} else {
			Failf("Failed to parse call: %s\n", s_call.CallName)
		}
	}
	return syzProg, ctx, nil
}

func parseCall(ctx *Context) (*prog.Call, error) {
	straceCall := ctx.CurrentStraceCall
	syzCallDef := ctx.Target.SyscallMap[straceCall.CallName]
	retCall := new(prog.Call)
	retCall.Meta = syzCallDef
	ctx.CurrentSyzCall = retCall

	Preprocess(ctx)
	if ctx.CurrentSyzCall.Meta == nil {
		//A call like fcntl may have variants like fcntl$get_flag
		//but no generic fcntl system call in Syzkaller
		return nil, nil
	}
	fmt.Printf("PARSING CALL: %s\n", ctx.CurrentSyzCall.Meta.CallName)
	retCall.Ret = strace_types.ReturnArg(ctx.CurrentSyzCall.Meta.Ret)

	if call := ParseMemoryCall(ctx); call != nil {
		return call, nil
	}
	if len(retCall.Meta.Args) != len(straceCall.Args) {
		fmt.Printf("syzkaller system call: " +
			"%s has %d arguments strace call: " +
			"%s has %d arguments",
			syzCallDef.CallName,
			len(syzCallDef.Args),
			straceCall.CallName,
			len(straceCall.Args))
	}
	for i := range(retCall.Meta.Args) {
		var strArg strace_types.Type = nil
		if i < len(straceCall.Args) {
			strArg = straceCall.Args[i]
		}
		if arg, err := parseArgs(retCall.Meta.Args[i], strArg, ctx); err != nil {
			Failf("Failed to parse arg: %s\n", err.Error())
		} else {
			retCall.Args = append(retCall.Args, arg)
		}
		//arg := syzCall.Args[i]
	}
	parseResult(retCall.Meta.Ret, straceCall.Ret, ctx)

	return retCall, nil
}

func parseResult(syzType prog.Type, straceRet int64, ctx *Context) {
	if straceRet > 0 {
		fmt.Printf("Parsing result\n")
		//TODO: This is a hack NEED to refacto lexer to parser return values into strace types
		straceExpr := strace_types.NewExpression(strace_types.NewIntType(straceRet))
		switch syzType.(type) {
		case *prog.ResourceType:
			fmt.Printf("Caching Ret: %d\n", straceRet)
			ctx.Cache.Cache(syzType, straceExpr, ctx.CurrentSyzCall.Ret)
		}
	}
}

func parseArgs(syzType prog.Type, straceArg strace_types.Type, ctx *Context) (prog.Arg, error) {
	if straceArg == nil {
		return GenDefaultArg(syzType, ctx), nil
	}
	switch a := syzType.(type) {
	case *prog.IntType, *prog.ConstType, *prog.FlagsType, *prog.LenType, *prog.CsumType:
		return Parse_ConstType(a, straceArg, ctx)
	case *prog.ProcType:
		return Parse_ProcType(a, straceArg, ctx)
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
	case *prog.VmaType:
		return Parse_VmaType(a, straceArg, ctx)
	default:
		panic(fmt.Sprintf("Unsupported  Type: %v\n", syzType))
	}
}

func Parse_VmaType(syzType *prog.VmaType, straceType strace_types.Type, ctx *Context) (prog.Arg, error) {
	npages := uint64(1)
	// TODO: strace doesn't give complete info, need to guess random page range
	if syzType.RangeBegin != 0 || syzType.RangeEnd != 0 {
		npages = uint64(int(syzType.RangeEnd)) // + r.Intn(int(a.RangeEnd-a.RangeBegin+1)))
	}
	arg := strace_types.PointerArg(syzType, 0, 0, npages, nil)
	ctx.State.Tracker.AddAllocation(ctx.CurrentSyzCall, pageSize, arg)
	return arg, nil
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
	case *strace_types.Field:
		return Parse_ArrayType(syzType, a.Val, ctx)
	case *strace_types.PointerType, *strace_types.Expression:
		return GenDefaultArg(syzType, ctx), nil
	default:
		Failf("Error parsing Array with Wrong Type: %s", straceType.Name())
	}
	return strace_types.GroupArg(syzType, args), nil
}

func Parse_StructType(syzType *prog.StructType, straceType strace_types.Type, ctx *Context) (prog.Arg, error) {
	fmt.Printf("Parsing struct type: %#v\n", syzType)
	args := make([]prog.Arg, 0)
	switch a := straceType.(type) {
	case *strace_types.StructType:
		args = append(args, evalFields(syzType.Fields, a.Fields, ctx)...)
	case *strace_types.ArrayType:
		//Syzkaller's pipe definition expects a pipefd struct
		//But strace returns an array type
		args = append(args, evalFields(syzType.Fields, a.Elems, ctx)...)
	case *strace_types.Field:
		fmt.Printf("Parsing Strace Field: %#v\n",  a)
		if arg, err := parseArgs(syzType, a.Val, ctx); err == nil {
			return arg, nil
		} else {
			Failf("Error parsing struct field: %#v", ctx)
		}
	default:
		Failf("Unsupported Strace Type: %#v to Struct Type", a)
	}
	fmt.Printf("Struct Type args: %p %#v\n", args, args)
	return strace_types.GroupArg(syzType, args), nil
}

func evalFields(syzFields []prog.Type, straceFields []strace_types.Type, ctx *Context) []prog.Arg {
	args := make([]prog.Arg, 0)
	j := 0
	for i, _ := range(syzFields) {
		if prog.IsPad(syzFields[i]) {
			args = append(args, prog.DefaultArg(syzFields[i]))
		} else {
			if j >= len(straceFields) {
				args = append(args, GenDefaultArg(syzFields[i], ctx))
			} else if arg, err := parseArgs(syzFields[i], straceFields[j], ctx); err == nil {
				args = append(args, arg)
			} else {
				Failf("Error parsing struct field: %#v", ctx)
			}
			j += 1
		}
	}
	return args
}

func Parse_UnionType(syzType *prog.UnionType, straceType strace_types.Type, ctx *Context) (prog.Arg, error) {
	switch strType := straceType.(type) {
	case *strace_types.Field:
		switch strValType := strType.Val.(type) {
		case *strace_types.Call:
			fmt.Printf("Parsing inner call\n")
			return ParseInnerCall(syzType, strValType, ctx), nil
		default:
			return Parse_UnionType(syzType, strType.Val, ctx)
		}
	default:
		idx := IdentifyUnionType(ctx)
		innerType := syzType.Fields[idx]
		if innerArg, err := parseArgs(innerType, straceType, ctx); err == nil {
			return strace_types.UnionArg(syzType, innerArg, innerType), nil
		} else {
			Failf("Error parsing union type: %#v", ctx)
		}
	}

	return nil, nil
}

func IdentifyUnionType(ctx *Context) int {
	switch ctx.CurrentStraceCall.CallName {
	case "bind", "connect":
		return IdentifyBindConnectUnionType(ctx)
	default:
		return 0
	}
}

func IdentifyBindConnectUnionType(ctx *Context) int {
	call := ctx.CurrentStraceCall
	switch strType := call.Args[1].(type) {
	case *strace_types.StructType:
		for i := range strType.Fields {
			switch strType.Fields[i].String() {
			case "AF_INET":
				return 1
			case "AF_UNIX":
				return 0
			case "AF_INET6":
				return 4
			default:
				return -1
			}
		}
	default:
		Failf("Failed to parse Bind/Connect Union Type. Strace Type: %#v\n", strType)
	}
	return -1
}

func Parse_BufferType(syzType *prog.BufferType, straceType strace_types.Type, ctx *Context) (prog.Arg, error) {
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
	case *strace_types.Expression:
		val := a.Eval(ctx.Target)
		bArr := make([]byte, 8)
		binary.LittleEndian.PutUint64(bArr, val)
		return strace_types.DataArg(syzType, bArr), nil
	case *strace_types.PointerType:
		val := a.Address
		bArr := make([]byte, 8)
		binary.LittleEndian.PutUint64(bArr, val)
		return strace_types.DataArg(syzType, bArr), nil
	case *strace_types.Field:
		return parseArgs(syzType, a.Val, ctx)
	default:
		Failf("Cannot parse type %s for Buffer Type\n", straceType.String())
	}
	return nil, nil
}

func Parse_PtrType(syzType *prog.PtrType, straceType strace_types.Type, ctx *Context) (prog.Arg, error) {
	switch a := straceType.(type) {
	case *strace_types.PointerType:
		if a.IsNull() {
			return prog.DefaultArg(syzType), nil
		} else {
			if a.Res == nil {
				res := GenDefaultArg(syzType.Type, ctx)
				return addr(ctx, syzType, res.Size(), res)
			}
			if res, err := parseArgs(syzType.Type, a.Res, ctx); err != nil {
				panic(fmt.Sprintf("Error parsing Ptr: %s", err.Error()))
			} else {
				return addr(ctx, syzType, res.Size(), res)
			}
		}
	case *strace_types.Expression:
		//Likely have a type of the form bind(3, 0xfffffffff, [3]);
		res := GenDefaultArg(syzType.Type, ctx)
		return addr(ctx, syzType, res.Size(), res)
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
	case *strace_types.DynamicType:
		return strace_types.ConstArg(syzType, a.BeforeCall.Eval(ctx.Target)), nil
	case *strace_types.ArrayType:
		/*
		Sometimes strace represents a pointer to int as [0] which gets parsed
		as Array([0], len=1). A good example is ioctl(3, FIONBIO, [1]).
		 */
		if a.Len == 0 {
			panic(fmt.Sprintf("Parsing const type. Got array type with len 0: %#v", ctx))
		}
		return Parse_ConstType(syzType, a.Elems[0], ctx)
	case *strace_types.StructType:
		/*
		Sometimes system calls have an int type that is actually a union. Strace will represent the union
		like a struct e.g.
		sigev_value={sival_int=-2123636944, sival_ptr=0x7ffd816bdf30}
		For now we choose the first option
		 */
		return Parse_ConstType(syzType, a.Fields[0], ctx)
	case *strace_types.Field:
		//We have an argument of the form sin_port=IntType(0)
		return parseArgs(syzType, a.Val, ctx)
	case *strace_types.Call:
		//We have likely hit a call like inet_pton, htonl, etc
		return ParseInnerCall(syzType, a, ctx), nil
	case *strace_types.BufferType:
		//The call almost certainly an error or missing fields
		return GenDefaultArg(syzType, ctx), nil
	        //E.g. ltp_bind01 two arguments are empty and
	case *strace_types.PointerType:
		/*
		This can be triggered by the following:
		2435  connect(3, {sa_family=0x2f ,..., 16)*/
		return strace_types.ConstArg(syzType, a.Address), nil
	default:
		Failf("Cannot convert Strace Type: %s to Const Type", straceType.Name())
	}
	return nil, nil
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
			res := strace_types.ResultArg(arg.Type(), arg, arg.Type().Default())
			return res, nil
		}
		res := strace_types.ResultArg(syzType, nil, val)
		return res, nil
	case *strace_types.Field:
		return Parse_ResourceType(syzType, a.Val, ctx)
	default:
		panic("Resource Type only supports Expression")
	}
}

func Parse_ProcType(syzType *prog.ProcType, straceType strace_types.Type, ctx *Context) (prog.Arg, error) {
	if syzType.Dir() == prog.DirOut {
		return GenDefaultArg(syzType, ctx), nil
	}
	switch a := straceType.(type) {
	case *strace_types.Expression:
		val := a.Eval(ctx.Target)
		if val >= syzType.ValuesPerProc {
			return strace_types.ConstArg(syzType, syzType.ValuesPerProc-1), nil
		} else {
			return strace_types.ConstArg(syzType, val), nil
		}
	case *strace_types.Field:
		return parseArgs(syzType, a.Val, ctx)
	case *strace_types.Call:
		return ParseInnerCall(syzType, a, ctx), nil
	case *strace_types.BufferType:
	/* Again probably an error case
	   Something like the following will trigger this
	    bind(3, {sa_family=AF_INET, sa_data="\xac"}, 3) = -1 EINVAL(Invalid argument)
	*/
		return GenDefaultArg(syzType, ctx), nil
	default:
		Failf("Unsupported Type for Proc: %#v\n", straceType)
	}
	return nil, nil
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
		case prog.BufferString:
			var data []byte
			if a.Kind == prog.BufferString && a.TypeSize != 0 {
				data = make([]byte, a.TypeSize)
			}
			return strace_types.DataArg(a, data)
		case prog.BufferFilename:
			var data []byte
			if a.Kind == prog.BufferFilename {
				data = make([]byte, 3)
			}
			return strace_types.DataArg(a, data)
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
	case *prog.ArrayType:
		return strace_types.GroupArg(a, nil)
	case *prog.ResourceType:
		return prog.MakeResultArg(syzType, nil, a.Desc.Type.Default())
	case *prog.VmaType:
		return prog.DefaultArg(syzType)
	default:
		panic(fmt.Sprintf("Unsupported Type: %#v", syzType))
	}
}

func addr(ctx *Context, syzTyp prog.Type, size uint64, data prog.Arg) (prog.Arg, error) {
	fmt.Printf("Adding address of size: %d\n", size)
	arg := strace_types.PointerArg(syzTyp, uint64(0), 0, 0, data)
	ctx.State.Tracker.AddAllocation(ctx.CurrentSyzCall, size, arg)
	return arg, nil
}