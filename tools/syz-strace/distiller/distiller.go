package distiller

import (
	"github.com/google/syzkaller/tools/syz-strace/domain"
	"github.com/google/syzkaller/prog"
	"sort"
	"fmt"
)

type Distiller interface {
	MinCover(domain.Seeds) []*prog.Prog
	Add(domain.Seeds)
	Contributes(domain.Seed, map[uint64]bool) int
}

type DefaultDistiller struct {
	DistilledProgs []*prog.Prog
	CallToSeed map[*prog.Call]*domain.Seed
	CallToDistilledProg map[*prog.Call]*prog.Prog
	CallToIdx map[*prog.Call]int
	SeedDependencyGraph map[*domain.Seed][]int
}

func NewDefaultDistiller() (d *DefaultDistiller) {
	d = &DefaultDistiller{
		DistilledProgs: make([]*prog.Prog, 0),
		CallToSeed: make(map[*prog.Call]*domain.Seed, 0),
		CallToDistilledProg: make(map[*prog.Call]*prog.Prog, 0),
		SeedDependencyGraph: make(map[*domain.Seed][]int, 0),
	}
	return
}

func (d *DefaultDistiller) Add(seeds domain.Seeds) {
	for _, seed := range seeds {
		d.CallToSeed[seed.Call] = seed
		d.SeedDependencyGraph[seed] = make([]int, 0)
		for call, idx := range seed.DependsOn {
			d.SeedDependencyGraph[seed] = append(d.SeedDependencyGraph[seed], idx)
			d.CallToIdx[call] = idx
		}
	}
}

func (d *DefaultDistiller) Contributes(seed *domain.Seed, seenIps map[uint64]bool) int {
	total := 0
	for _, ip := range seed.Cover {
		if _, ok := seenIps[ip]; !ok {
			seenIps[ip] = true
			total += 1
		}
	}
	return total
}

func (d *DefaultDistiller) MinCover(seeds domain.Seeds) (distilled []*prog.Prog) {
	fmt.Printf("Computing Min Cover with %d seeds\n", len(seeds))
	seenIps := make(map[uint64]bool)
	sort.Sort(sort.Reverse(seeds))
	contributing_progs := 0
	for _, seed := range seeds {
		var ips int = d.Contributes(seed, seenIps)
		if ips > 0 {
			d.AddToDistilledProg(seed)
			fmt.Printf("Seed: %s contributes: %d ips out of its total of: %d\n", seed.Call.Meta.Name, ips, len(seed.Cover))
			contributing_progs += 1
		}
	}
	distilledProgs := make(map[*prog.Prog]bool)
	for _, seed := range seeds {
		if _, ok := d.CallToDistilledProg[seed.Call]; ok {
			distilledProgs[d.CallToDistilledProg[seed.Call]] = true
		}
	}
	for prog, _ := range distilledProgs {
		fmt.Printf("Prog: %v\n", prog)
		distilled = append(distilled, prog)
	}
	fmt.Printf("Total Contributing: %d, out of %d", contributing_progs, len(seeds))
	return
}

func (d *DefaultDistiller) TrackDependencies(prg *prog.Prog) {
	args := make(map[*prog.Arg]int, 0)
	for i, call := range prg.Calls {
		var seed *domain.Seed
		var ok bool
		if seed, ok = d.CallToSeed[call]; !ok {
			//Most likely an mmap we had to do
			fmt.Printf("Call: %s\n", call.Meta.CallName)
			continue
		}
		for _, arg := range call.Args {
			fmt.Printf("Arg: %s, %v\n", call.Meta.CallName, arg)
			upstream_maps := d.isDependent(arg, i, args)
			for k, _ := range upstream_maps {
				fmt.Printf("K: %d\n", k)
				d.SeedDependencyGraph[seed] = append(d.SeedDependencyGraph[seed], k)
			}
		}
		fmt.Printf("depends on: %v\n", d.SeedDependencyGraph[seed])
		args[call.Ret] = i
	}
}

func (d *DefaultDistiller) AddToDistilledProg(seed *domain.Seed) {
	upstream_calls := d.SeedDependencyGraph[seed]
	/* We merge the programs of any calls we depend on */
	if d.CallToDistilledProg[seed.Call] != nil {
		return
	}
	progsToMerge := make([]*prog.Prog, 0)
	for _, idx := range upstream_calls {
		call := seed.Prog.Calls[idx]
		if _, ok := d.CallToDistilledProg[call]; ok {
			progsToMerge = append(progsToMerge, d.CallToDistilledProg[call])
		}
	}
	if len(progsToMerge) == 0 {
		/* If none of our upstream calls have programs, we create a new one and
		 * add all our upstream dependencies
		 */
		distProg := new(prog.Prog)
		distProg.Calls = make([]*prog.Call, 0)
		//Add the calls in sorted order of their position in the original program
		sort.Ints(d.SeedDependencyGraph[seed])
		fmt.Printf("dependency: %v\n", d.SeedDependencyGraph[seed])
		for _, idx := range d.SeedDependencyGraph[seed] {
			distProg.Calls = append(distProg.Calls, seed.Prog.Calls[idx])
			d.CallToDistilledProg[seed.Prog.Calls[idx]] = distProg
		}
		distProg.Calls = append(distProg.Calls, seed.Call)
		d.CallToDistilledProg[seed.Call] = distProg
	} else if len(progsToMerge) == 1 {
		progsToMerge[0].Calls = append(progsToMerge[0].Calls, seed.Call)
	} else {
		fmt.Printf("HANDLING THIRD CASE\n")
		distProg := new(prog.Prog)
		distProg.Calls = make([]*prog.Call, 0)
		idxToCall := make(map[int]*prog.Call, 0)
		callIndexes := make([]int, 0)
		for _, p := range progsToMerge {
			for _, call := range p.Calls {
				idxToCall[d.CallToIdx[call]] = call
				callIndexes = append(callIndexes, d.CallToIdx[call])
			}
		}
		sort.Ints(callIndexes)
		for _, idx := range callIndexes {
			call := idxToCall[idx]
			distProg.Calls = append(distProg.Calls, call)
			d.CallToDistilledProg[call] = distProg
		}
		d.CallToDistilledProg[seed.Call] = distProg
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

