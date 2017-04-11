package distiller

import (
	"github.com/google/syzkaller/tools/syz-strace/domain"
	"github.com/google/syzkaller/prog"
	"sort"
	"fmt"
)

type Distiller interface {
	MinCover(domain.Seeds) *prog.Prog
	Add(domain.Seeds)
}

type DefaultDistiller struct {
	DistilledProgs []*prog.Prog
	SeedLookup map[*prog.Call]*domain.Seed
	CallToDistilledProg map[*prog.Call]*prog.Prog
	SeedDependencyGraph map[*domain.Seed][]*prog.Call
}

func NewDefaultDistiller() (d *DefaultDistiller) {
	d = &DefaultDistiller{
		DistilledProgs: make([]*prog.Prog, 0),
		SeedLookup: make(map[*prog.Call]*domain.Seed, 0),
		CallToDistilledProg: make(map[*prog.Call]*prog.Prog),
		SeedDependencyGraph: make(map[*domain.Seed][]*prog.Call, 0),
	}
	return
}

func (d *DefaultDistiller) Add(seeds domain.Seeds) {
	for _, seed := range seeds {
		d.SeedLookup[seed.Call] = seed
		d.SeedDependencyGraph[seed] = make([]*prog.Call, 0)
		d.CallToDistilledProg[seed.Call] = nil
	}
}

func (d *DefaultDistiller) MinCover(seeds domain.Seeds) *prog.Prog {
	fmt.Printf("Computing Min Cover with %d seeds", len(seeds))
	seenIps := make(map[uint64]bool)
	sort.Reverse(seeds)
	contributing_progs := 0
	for _, seed := range seeds {
		var ips int = seed.Contributes(seenIps)
		if ips > 0 {
			fmt.Printf("Seed: %s contributes: %d ips", seed.Call.Meta.Name, ips)
			contributing_progs += 1
		}
	}
	fmt.Printf("Total Contributing: %d, out of %d", contributing_progs, len(seeds))
	return nil
}

func (d *DefaultDistiller) TrackDependencies(prg *prog.Prog, args map[*prog.Arg]int) {
	for i, call := range prg.Calls {
		var seed *domain.Seed
		var ok bool
		if seed, ok = d.SeedLookup[call]; !ok {
			continue
		}
		for _, arg := range call.Args {
			//fmt.Printf("Arg: %s, %v\n", call.Meta.CallName, arg)
			upstream_maps := d.isDependent(arg, i, args)
			for k, _ := range upstream_maps {
				d.SeedDependencyGraph[seed] = append(d.SeedDependencyGraph[seed], prg.Calls[k])
			}
		}
		args[call.Ret] = i
	}
}

func (d *DefaultDistiller) isDependent(arg *prog.Arg, callIdx int, args map[*prog.Arg]int) map[int]bool {
	upstreamSet := make(map[int]bool, 0)
	if arg == nil {
		return nil
	}
	//May need to support more kinds
	switch arg.Kind {
	case prog.ArgResult:
		//fmt.Printf("%v\n", args[arg.Res])
		if _, ok := args[arg.Res]; ok {
			upstreamSet[args[arg.Res]] = true
		}
	case prog.ArgPointer:
		if _, ok := args[arg.Res]; ok {
			upstreamSet[args[arg.Res]] = true
		} else {
			for k, _ := range d.isDependent(arg.Res, callIdx, args) {
				upstreamSet[k] = true
			}
		}

	case prog.ArgGroup:
		for _, inner_arg := range arg.Inner {
			innerArgMap := d.isDependent(inner_arg, callIdx, args)
			for k, _ := range innerArgMap {
				upstreamSet[k] = true
			}
		}

	}
	args[arg] = callIdx
	//doesn't hurt to add again if it was already added
	return upstreamSet
}