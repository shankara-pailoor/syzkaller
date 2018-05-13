package parser

import (
	"github.com/google/syzkaller/prog"
	"github.com/google/syzkaller/tools/moonshine/strace_types"
	"github.com/google/syzkaller/tools/moonshine/tracker"
)

type TypePair struct {
	straceType strace_types.Type
	syzkallerType prog.Type
}

type returnCache map[ResourceDescription]prog.Arg

type ResourceDescription struct {
	Type string
	Val string
}

type Context struct {
	cache *returnCache
	currentStraceCall *strace_types.Syscall
	state *tracker.State
	target *prog.Target
}

type ArgParseHandler func(strace_types.Type, prog.Type, ctx *Context) (prog.Arg, error)

/*
argHandlers := make(map[TypePair]ArgParseHandler, 0)

func parseCall(ctx *Context) (*prog.Call, error) {
	straceCall := ctx.currentStraceCall
	callMeta := ctx.target.SyscallMap[straceCall.CallName]
	var straceArg strace_types.Type
	for i, argTyp := range callMeta.Args {
		straceArg = straceCall.Args[i]

	}
}*/
