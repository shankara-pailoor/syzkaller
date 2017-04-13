package distiller

import (
	"github.com/google/syzkaller/tools/syz-strace/domain"
	"github.com/google/syzkaller/prog"
	"sort"
	"fmt"
	"github.com/google/syzkaller/tools/syz-strace/config"
	"io/ioutil"
)

type Distiller interface {
	Distill([]*prog.Prog) []*prog.Prog
	Add(domain.Seeds)
	Contributes(*domain.Seed, map[uint64]bool) int
	Stats(domain.Seeds)
}

type DefaultDistiller struct {
	StatFile string
	Seeds domain.Seeds
	DistilledProgs []*prog.Prog
	CallToSeed map[*prog.Call]*domain.Seed
	CallToDistilledProg map[*prog.Call]*prog.Prog
	CallToIdx map[*prog.Call]int
	SeedDependencyGraph map[*domain.Seed]map[int]map[*prog.Arg][]*prog.Arg
}

func NewDistiller(conf config.DistillConfig) (d Distiller){
	switch (conf.Type) {
	case "default":
		d = NewDefaultDistiller(conf)
	default:
		d = NewDefaultDistiller(conf)
	}
	return
}

func NewDefaultDistiller(conf config.DistillConfig) (d *DefaultDistiller) {
	d = &DefaultDistiller{
		StatFile: conf.Stats,
		DistilledProgs: make([]*prog.Prog, 0),
		CallToSeed: make(map[*prog.Call]*domain.Seed, 0),
		CallToDistilledProg: make(map[*prog.Call]*prog.Prog, 0),
		CallToIdx: make(map[*prog.Call]int, 0),
		SeedDependencyGraph: make(map[*domain.Seed]map[int]map[*prog.Arg][]*prog.Arg, 0),
	}
	return
}

func (d *DefaultDistiller) Add(seeds domain.Seeds) {
	d.Seeds = seeds
	for _, seed := range seeds {
		d.CallToSeed[seed.Call] = seed
		d.SeedDependencyGraph[seed] = make(map[int]map[*prog.Arg][]*prog.Arg, 0)
		seed.ArgMeta = make(map[*prog.Arg]bool, 0)
		for call, idx := range seed.DependsOn {
			if _, ok := d.SeedDependencyGraph[seed][idx]; !ok {
				d.SeedDependencyGraph[seed][idx] = make(map[*prog.Arg][]*prog.Arg, 0)
			}
			d.CallToIdx[call] = idx
		}
		d.CallToIdx[seed.Call] = seed.CallIdx
	}
}

func (d *DefaultDistiller) Stats(distilledSeeds domain.Seeds) {
	totalCalls := d.Seeds.Len()
	distilledCalls := distilledSeeds.Len()
	if d.StatFile == "" {
		fmt.Printf("Total Calls: %d, Distilled: %d", totalCalls, distilledCalls)
	} else {
		data := fmt.Sprintf("Total Calls: %d, Distilled: %d", totalCalls, distilledCalls)
		ioutil.WriteFile(d.StatFile, []byte(data), 0600)
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

func (d *DefaultDistiller) Distill(progs []*prog.Prog) (distilled []*prog.Prog) {
	seenIps := make(map[uint64]bool)
	seeds := d.Seeds
	fmt.Printf("Computing Min Cover with %d seeds\n", len(seeds))
	sort.Sort(sort.Reverse(seeds))
	contributing_progs := 0
	heavyHitters := make(domain.Seeds, 0)
	for _, prog := range progs {
		d.TrackDependencies(prog)
	}
	for _, seed := range seeds {
		var ips int = d.Contributes(seed, seenIps)
		if ips > 0 {
			heavyHitters.Add(seed)
			fmt.Printf("Seed: %s contributes: %d ips out of its total of: %d\n", seed.Call.Meta.Name, ips, len(seed.Cover))
			contributing_progs += 1
		}
	}
	d.Stats(heavyHitters)
	for _, seed := range heavyHitters {
		d.AddToDistilledProg(seed)
	}
	distilledProgs := make(map[*prog.Prog]bool)
	for _, seed := range seeds {
		if _, ok := d.CallToDistilledProg[seed.Call]; ok {
			distilledProgs[d.CallToDistilledProg[seed.Call]] = true
		}
	}
	for prog, _ := range distilledProgs {
		//fmt.Printf("Prog: %v\n", prog)
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
			//fmt.Printf("Call: %s\n", call.Meta.CallName)
			continue
		}
		for _, arg := range call.Args {
			//fmt.Printf("Arg: %s, %v\n", call.Meta.CallName, arg)
			upstream_maps := d.isDependent(arg, i, args)
			for k, argMap := range upstream_maps {
				//fmt.Printf("K: %d\n", k)
				if d.SeedDependencyGraph[seed][k] == nil {
					d.SeedDependencyGraph[seed][k] = make(map[*prog.Arg][]*prog.Arg, 0)
				}
				for argK, argVs := range argMap {
					//fmt.Printf("ARGVs: %v\n", argVs)
					d.SeedDependencyGraph[seed][k][argK] = append(d.SeedDependencyGraph[seed][k][argK], argVs...)
				}
			}
		}
		//fmt.Printf("depends on: %v\n", d.SeedDependencyGraph[seed])
		if call.Ret != nil {
			args[call.Ret] = i
		}
	}
}

func (d *DefaultDistiller) GetAllUpstreamDependents(seed *domain.Seed) []*prog.Call {
	calls := make([]*prog.Call, 0)
	callMap := make(map[*prog.Call]bool, 0)
	for idx, _ := range d.SeedDependencyGraph[seed] {
		call := seed.Prog.Calls[idx]
		if s, ok := d.CallToSeed[call]; ok {
			calls = append(calls, call)
			calls = append(calls, d.GetAllUpstreamDependents(s)...)
		} else {
			calls = append(calls, call)
		}
	}
	for _, call := range calls {
		callMap[call] = true
	}
	calls = make([]*prog.Call, 0)
	for k, _ := range callMap {
		calls = append(calls, k)
	}
	return calls
}

func (d *DefaultDistiller) AddToDistilledProg(seed *domain.Seed) {
	distilledProg := new(prog.Prog)
	distilledProg.Calls = make([]*prog.Call, 0)
	callIndexes := make([]int, 0)
	totalCalls := make([]*prog.Call, 0)

	if d.CallToDistilledProg[seed.Call] != nil {
		return
	}
	upstreamCalls := d.GetAllUpstreamDependents(seed)
	distinctProgs := d.getAllProgs(upstreamCalls)
	if len(distinctProgs) > 0 {
		totalCalls = append(d.getCalls(distinctProgs), upstreamCalls...)
	} else {
		totalCalls = upstreamCalls
	}

	callIndexes = d.uniqueCallIdxs(totalCalls)

	callIndexes = append(callIndexes, seed.CallIdx)

	//fmt.Printf("Call IDX: %v\n", callIndexes)
	for _, idx := range callIndexes {
		call := seed.Prog.Calls[idx]
		d.CallToDistilledProg[call] = distilledProg
		distilledProg.Calls = append(distilledProg.Calls, call)
	}
	for _, call := range distilledProg.Calls {
		if s, ok := d.CallToSeed[call]; ok {
			//fmt.Printf("HERE\n")
			dependencyMap := d.SeedDependencyGraph[s]
			for idx, argMap := range dependencyMap {
				upstreamSeed := d.CallToSeed[seed.Prog.Calls[idx]]
				for argK, argVs := range argMap {
					//fmt.Printf("dealing with argMap\n")
					for _, argV := range argVs {
						if _, ok := upstreamSeed.ArgMeta[argK]; !ok {
							//fmt.Printf("UpstreamedSeed: %s, index: %d\n", upstreamSeed.Call.Meta.CallName, idx)
							argK.Uses = nil
							upstreamSeed.ArgMeta[argK] = true
						}
						if argK.Uses == nil {
							//fmt.Printf("Allocating Uses: %s, index: %d\n", upstreamSeed.Call.Meta.CallName, idx)
							argK.Uses = make(map[*prog.Arg]bool, 0)
						}
						//fmt.Printf("Setting ArgV: %s, %d\n", upstreamSeed.Call.Meta.CallName, idx)
						argK.Uses[argV] = true
					}

				}
			}
		}
	}
	seed.Call.Ret.Uses = nil
}

func (d *DefaultDistiller) uniqueCallIdxs(calls []*prog.Call) []int {
	seenCalls := make(map[*prog.Call]bool, 0)
	ret := make([]int, 0)

	for _, call := range calls {
		if _, ok := seenCalls[call]; !ok {
			seenCalls[call] = true
			ret = append(ret, d.CallToIdx[call])
		}
	}
	sort.Ints(ret)
	return ret
}

func (d *DefaultDistiller) getAllProgs(calls []*prog.Call) (ret []*prog.Prog) {
	distinctProgs := make(map[*prog.Prog]bool)
	for _, call := range calls {
		if _, ok := d.CallToDistilledProg[call]; ok {
			distinctProgs[d.CallToDistilledProg[call]] = true
		}
	}
	for k, _ := range distinctProgs {
		ret = append(ret, k)
	}
	return
}

func (d *DefaultDistiller) getCalls(progs []*prog.Prog) (ret []*prog.Call) {
	for _, p := range progs {
		ret = append(ret, p.Calls...)
	}
	return
}

func (d *DefaultDistiller) Clean(progDistilled *prog.Prog) {

}

func (d *DefaultDistiller) isDependent(arg *prog.Arg, callIdx int, args map[*prog.Arg]int) map[int]map[*prog.Arg][]*prog.Arg {
	upstreamSet := make(map[int]map[*prog.Arg][]*prog.Arg, 0)
	if arg == nil {
		return nil
	}
	//May need to support more kinds
	switch arg.Kind {
	case prog.ArgResult:
		//fmt.Printf("%v\n", args[arg.Res])
		if _, ok := args[arg.Res]; ok {
			if upstreamSet[args[arg.Res]] == nil {
				upstreamSet[args[arg.Res]] = make(map[*prog.Arg][]*prog.Arg, 0)
				upstreamSet[args[arg.Res]][arg.Res] = make([]*prog.Arg, 0)
			}
			upstreamSet[args[arg.Res]][arg.Res] = append(upstreamSet[args[arg.Res]][arg.Res], arg)
		}
	case prog.ArgPointer:
		if _, ok := args[arg.Res]; ok {
			dep := upstreamSet[args[arg.Res]][arg.Res]
			dep = append(dep, arg)
		} else {
			for k, argMap := range d.isDependent(arg.Res, callIdx, args) {
				if upstreamSet[k] == nil {
					upstreamSet[k] = make(map[*prog.Arg][]*prog.Arg)
					upstreamSet[k] = argMap
				} else {
					for argK, argVs := range argMap {
						upstreamSet[k][argK] = append(upstreamSet[k][argK], argVs...)
					}
				}
			}
		}

	case prog.ArgGroup:
		for _, inner_arg := range arg.Inner {
			for k, argMap := range d.isDependent(inner_arg, callIdx, args) {
				if upstreamSet[k] == nil {
					upstreamSet[k] = make(map[*prog.Arg][]*prog.Arg)
					upstreamSet[k] = argMap
				} else {
					for argK, argVs := range argMap {
						upstreamSet[k][argK] = append(upstreamSet[k][argK], argVs...)
					}
				}
			}
		}
	}
	args[arg] = callIdx
	//doesn't hurt to add again if it was already added
	return upstreamSet
}

