package main

import (
	"github.com/google/syzkaller/tools/syz-strace/domain"
	"github.com/google/syzkaller/prog"
	sparser "github.com/mattrco/difftrace/parser"

	"strings"
	"fmt"
	"strconv"
)

func PreProcessItimerval(strace_arg *string){
	if strace_arg != nil && len(*strace_arg) > 1 {
		if (*strace_arg)[0] == '[' {
			out := []rune(*strace_arg)
			out[0] = '{'
			out[len(*strace_arg)-1] = '}'
			*strace_arg = string(out)
		}
	}
}

func ParseTimeval(typ prog.Type, strace_arg string,
			consts *map[string]uint64,
			return_vars *map[returnType]prog.Arg,
			line *sparser.OutputLine,
			s *domain.State) (prog.Arg, []*prog.Call, error) {

		//This is a particular field of the socket operation with optname SO_SNDTIMEO
		//inner_args := make([]Arg, 0)
	st := typ.(*prog.StructType)
	if strings.Contains(strace_arg, "\"") {
		strace_arg = strace_arg[1 : len(strace_arg)-1]
		split := strings.Split(strace_arg, "\\")
		fmt.Printf("SPECIFIC STRUCT SPLIT %v\n", split)
		timeout_secs, err := strconv.ParseUint(strings.Split(strace_arg, "\\")[1], 10, 64)
		if err != nil {
			panic(fmt.Sprintf("Error parsing timeout_secs in specific structs: %s\n", err.Error()))
		}
		timeout_usecs := uint64(0)
		fmt.Printf("FIELD TYPE NAME:%s\n", st.Fields[0])
		arg := groupArg(typ, []prog.Arg{resultArg(st.Fields[0], nil, timeout_secs), resultArg(st.Fields[1], nil, timeout_usecs)})
		return arg, nil, nil
	} else {
		args := make([]prog.Arg, 0)
		struct_args := make([]string, 0)
		strace_arg = strace_arg[1:len(strace_arg)-1]
		for len(strace_arg) > 0 {
			param, rem := ident(strace_arg)
			fmt.Printf("Param: %s, Rem: %s\n", param, rem)
			strace_arg = rem
			struct_args = append(struct_args, param)
		}
		for i, strace_arg := range struct_args {
			if strings.Contains(strace_arg, "=") {
				kv := strings.SplitN(strace_arg, "=", 2)
				timeout_secs, err := strconv.ParseUint(kv[1], 10, 64)
				if err != nil {
					failf("Failed to parse int")
				}
				args = append(args, resultArg(st.Fields[i], nil, timeout_secs))
			}
		}
		arg := groupArg(typ, args)
		return arg, nil, nil
	}
}
