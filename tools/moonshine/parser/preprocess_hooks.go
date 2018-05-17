package parser

import (
	"github.com/google/syzkaller/tools/moonshine/strace_types"
	"github.com/google/syzkaller/prog"
	"fmt"
)

type PreprocessHook func(ctx *Context)

func Preprocess(ctx *Context) {
	call := ctx.CurrentStraceCall.CallName
	if procFunc, ok := PreprocessMap[call]; ok {
		procFunc(ctx)
	}
	return
}

var PreprocessMap = map[string]PreprocessHook {
	"accept": Preprocess_Accept,
	"bind": Preprocess_Bind,
	"getsockopt": Preprocess_Getsockopt,
	"ioctl": Preprocess_Ioctl,
	"open": Preprocess_Open,
	"openat": Preprocess_Openat,
	"setsockopt": Preprocess_Setsockopt,
	"socket": Preprocess_Socket,
}


func Preprocess_Accept(ctx *Context) {
	/*
	Accept can take on many subforms such as
	accept$inet
	accept$inet6

	In order to determine the proper form we need to look at the file descriptor to determine
	the proper socket type. We refer to the $inet as a suffix to the name
	 */
	suffix := ""
	straceFd := ctx.CurrentStraceCall.Args[0] //File descriptor of Accept
	syzFd := ctx.CurrentSyzCall.Meta.Args[0]
	if arg := ctx.Cache.Get(syzFd, straceFd); arg != nil {
		switch a := arg.Type().(type) {
		case *prog.ResourceType:
			if suffix = strace_types.Accept_labels[a.TypeName]; suffix != "" {
				ctx.CurrentStraceCall.CallName += suffix
				ctx.CurrentSyzCall.Meta = ctx.Target.SyscallMap[ctx.CurrentStraceCall.CallName]
			}
		}
	}
}

func Preprocess_Bind(ctx *Context) {
	suffix := ""
	straceFd := ctx.CurrentStraceCall.Args[0]
	syzFd := ctx.CurrentSyzCall.Meta.Args[0]
	if arg := ctx.Cache.Get(syzFd, straceFd); arg != nil {
		switch a := arg.Type().(type) {
		case *prog.ResourceType:
			if suffix = strace_types.Bind_labels[a.TypeName]; suffix != "" {
				ctx.CurrentStraceCall.CallName += suffix
				ctx.CurrentSyzCall.Meta = ctx.Target.SyscallMap[ctx.CurrentStraceCall.CallName]
			}
		}
	}
}

func Preprocess_Socket(ctx *Context) {
	straceFd := ctx.CurrentStraceCall.Args[0]
	sockType := ctx.CurrentStraceCall.Args[1]
	pair := strace_types.Pair{
		A: straceFd.String(),
		B: sockType.String(),
	}

	if suffix, ok := strace_types.Socket_labels_pair[pair]; ok {
		ctx.CurrentStraceCall.CallName += suffix
		ctx.CurrentSyzCall.Meta = ctx.Target.SyscallMap[ctx.CurrentStraceCall.CallName]
	}
}

func Preprocess_Setsockopt(ctx *Context) {
	sockLevel := ctx.CurrentStraceCall.Args[1]
	optName := ctx.CurrentStraceCall.Args[2]
	pair := strace_types.Pair {
		A: sockLevel.String(),
		B: optName.String(),
	}
	if suffix, ok := strace_types.Setsockopt_labels[pair]; ok {
		ctx.CurrentStraceCall.CallName += suffix
		ctx.CurrentSyzCall.Meta = ctx.Target.SyscallMap[ctx.CurrentStraceCall.CallName]
	}

}

func Preprocess_Getsockopt(ctx *Context) {
	sockLevel := ctx.CurrentStraceCall.Args[1]
	optName := ctx.CurrentStraceCall.Args[2]
	pair := strace_types.Pair {
		A: sockLevel.String(),
		B: optName.String(),
	}
	if suffix, ok := strace_types.Getsockopt_labels[pair]; ok {
		ctx.CurrentStraceCall.CallName += suffix
		ctx.CurrentSyzCall.Meta = ctx.Target.SyscallMap[ctx.CurrentStraceCall.CallName]
	}

}

func Preprocess_Open(ctx *Context) {
	if len(ctx.CurrentStraceCall.Args) < 3 {
		ctx.CurrentStraceCall.Args = append(ctx.CurrentStraceCall.Args,
			strace_types.NewExpression(strace_types.NewIntType(int64(0))))
	}
}

func Preprocess_Openat(ctx *Context) {
	if len(ctx.CurrentSyzCall.Args) < 4 {
		ctx.CurrentStraceCall.Args = append(ctx.CurrentStraceCall.Args,
			strace_types.NewExpression(strace_types.NewIntType(int64(0))))
	}
}

func Preprocess_Ioctl(ctx *Context) {
	ioctlCmd := ctx.CurrentStraceCall.Args[1].String()
	fmt.Printf("IOCTL CMD: %s\n", ioctlCmd)
	if suffix, ok := strace_types.Ioctl_map[ioctlCmd]; ok {
		ctx.CurrentStraceCall.CallName += suffix
	}
	if _, ok := ctx.Target.SyscallMap[ctx.CurrentStraceCall.CallName + "$" + ioctlCmd]; ok {
		ctx.CurrentStraceCall.CallName += "$"+ioctlCmd
		fmt.Printf("Meta: %#v\n", ctx.CurrentSyzCall.Meta)
		ctx.CurrentSyzCall.Meta = ctx.Target.SyscallMap[ctx.CurrentStraceCall.CallName]
		fmt.Printf("Meta: %#v\n", ctx.CurrentSyzCall.Meta)
	}
}