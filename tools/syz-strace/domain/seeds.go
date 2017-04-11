package domain

import (
	"github.com/google/syzkaller/prog"
)

type Seed struct {
	Call *prog.Call
	Prog *prog.Prog
	Cover []uint64
	CallIdx int /* Index in the Prog call array */
}

type Seeds []*Seed

func (s Seeds) Len() int {
	return len(s)
}

func (s Seeds) Swap(i, j int) {
	s[i], s[j] = s[j], s[i]
}

func (s Seeds) Less(i, j int) bool {
	return len(s[i].Cover) < len(s[j].Cover)
}

func (s *Seeds) Add(seed *Seed) {
	*s = append(*s, seed)
}

func NewSeed(call *prog.Call, prog *prog.Prog, idx int, cover []uint64) *Seed{
	return &Seed {
		Call: call,
		Prog: prog,
		Cover: cover,
		CallIdx: idx,
	}
}
