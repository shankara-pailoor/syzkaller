package main

import (
	"github.com/google/syzkaller/prog"
	sparser "github.com/mattrco/difftrace/parser"
	"github.com/google/syzkaller/tools/syz-strace/domain"
)

func ParseIcmpFilter(typ prog.Type, strace_arg string,
			consts *map[string]uint64,
			return_vars *map[returnType]prog.Arg,
			line *sparser.OutputLine,
			s *domain.State) (prog.Arg,
					  []*prog.Call,
					  error) {
	//Only has one field which is integer type
	st := typ.(*prog.StructType)
	arg_, calls_, err_ := parseArg((st.Fields[0]).(*prog.IntType), strace_arg, consts, return_vars, line, s)
	return groupArg(typ, []prog.Arg{arg_}), calls_, err_
}



