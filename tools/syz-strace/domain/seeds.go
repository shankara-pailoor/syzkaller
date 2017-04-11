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

func (s Seeds) Add(seed *Seed) {
	s = append(s, seed)
}

func (s *Seed) Contributes(seenIps map[uint64]bool) (total int) {
	total = 0
	for _, ip := range s.Cover {
		if _, ok := seenIps[ip]; !ok {
			total += 1
		}
	}
	return total
}

func NewSeed(call *prog.Call, prog *prog.Prog, idx int, cover []uint64) *Seed{
	return &Seed {
		Call: call,
		Prog: prog,
		Cover: cover,
		CallIdx: idx,
	}
}
