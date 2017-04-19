package distiller

import (
	"github.com/google/syzkaller/prog"
	"github.com/google/syzkaller/tools/syz-strace/domain"
	"fmt"
	"sort"
)

func (d *StrongDistiller) Add(seeds domain.Seeds) {
	d.Seeds = seeds
	for _, seed := range seeds {
		d.CallToSeed[seed.Call] = seed
		d.UpstreamDependencyGraph[seed] = make(map[int]map[*prog.Arg][]*prog.Arg, 0)
		seed.ArgMeta = make(map[*prog.Arg]bool, 0)
		for call, idx := range seed.DependsOn {
			if _, ok := d.UpstreamDependencyGraph[seed][idx]; !ok {
				d.UpstreamDependencyGraph[seed][idx] = make(map[*prog.Arg][]*prog.Arg, 0)
			}
			d.CallToIdx[call] = idx
		}
		d.CallToIdx[seed.Call] = seed.CallIdx
	}
}

func (d *StrongDistiller) Distill(progs []*prog.Prog) (distilled []*prog.Prog) {
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


func (d *StrongDistiller) AddToDistilledProg(seed *domain.Seed) {
	distilledProg := new(prog.Prog)
	distilledProg.Calls = make([]*prog.Call, 0)
	callIndexes := make([]int, 0)
	totalCalls := make([]*prog.Call, 0)

	if d.CallToDistilledProg[seed.Call] != nil {
		return
	}
	seenMap := make(map[int]bool, 0)
	upstreamCalls := make([]*prog.Call, 0)
	upstreamCalls = append(upstreamCalls, d.GetAllUpstreamDependents(seed, seenMap)...)
	upstreamCalls = append(upstreamCalls, seed.Call)
	distinctProgs := d.getAllProgs(upstreamCalls)
	if len(distinctProgs) > 0 {
		totalCalls = append(d.getCalls(distinctProgs), upstreamCalls...)
	} else {
		totalCalls = upstreamCalls
	}

	callIndexes = d.uniqueCallIdxs(totalCalls)
	for _, idx := range callIndexes {
		call := seed.Prog.Calls[idx]
		d.CallToDistilledProg[call] = distilledProg
		distilledProg.Calls = append(distilledProg.Calls, call)
	}
	d.BuildDependency(seed, distilledProg)
}
