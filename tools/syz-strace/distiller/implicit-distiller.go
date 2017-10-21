package distiller

import (
	"github.com/google/syzkaller/tools/syz-strace/domain"
	"github.com/google/syzkaller/prog"
	"github.com/google/syzkaller/tools/syz-strace/implicit-dependencies"
	"fmt"
	"sort"
	"os"
	"strings"
)

type ImplicitDistiller struct {
	*DistillerMetadata
	impl_deps implicit_dependencies.ImplicitDependencies
}

func (d *ImplicitDistiller) Add(seeds domain.Seeds) {
	//fmt.Println(d.impl_deps["msync"])
	d.Seeds = seeds
	for _, seed := range seeds {
		d.CallToSeed[seed.Call] = seed
		d.UpstreamDependencyGraph[seed] = make(map[int]map[prog.Arg][]prog.Arg, 0)
		seed.ArgMeta = make(map[prog.Arg]bool, 0)
		for call,idx := range seed.DependsOn {
			if _, ok := d.UpstreamDependencyGraph[seed][idx]; !ok {
				d.UpstreamDependencyGraph[seed][idx] = make(map[prog.Arg][]prog.Arg, 0)
			}
			d.CallToIdx[call] = idx
		}
		d.CallToIdx[seed.Call] = seed.CallIdx
	}
}

func (d *ImplicitDistiller) Distill(progs []*prog.Prog) (distilled []*prog.Prog) {
	seenIps := make(map[uint64]bool)
	seeds := d.Seeds
	fmt.Printf("Performing implicit distillation with %d seeds\n", len(seeds))
	sort.Sort(sort.Reverse(seeds))  // sort seeds by inidividual coverage.
	contributing_seeds := 0
	heavyHitters := make(domain.Seeds, 0)
	seedOnly := false
	for _, prog := range progs {
		d.TrackDependencies(prog)
	}
	for _, seed := range seeds {
		ips := d.Contributes(seed, seenIps)  /* how many unique Ips does seed contribute */
		if ips > 0 {
			heavyHitters.Add(seed)
			fmt.Printf("Seed: %s contributes: %d ips out of its total of: %d\n", seed.Call.Meta.Name, ips, len(seed.Cover))
			contributing_seeds += 1
		}
	}
	for _, seed := range heavyHitters {
		d.AddToDistilledProg(seed, seedOnly)
	}
	distilledProgs := make(map[*prog.Prog]bool)
	for _, seed := range seeds {
		if _, ok := d.CallToDistilledProg[seed.Call]; ok {
			distilledProgs[d.CallToDistilledProg[seed.Call]] = true
		}
	}
	for prog, _ := range distilledProgs {
		d.CallToSeed[prog.Calls[0]].State.Tracker.FillOutMemory(prog)
		distilled = append(distilled, prog)
	}
	fmt.Fprintf(os.Stderr,
		"Total Contributing seeds: %d out of %d, in %d implicitly-distilled programs using seedonly %t\n",
		contributing_seeds, len(seeds), len(distilled), seedOnly,
	)
	return
}

func (d *ImplicitDistiller) AddToDistilledProg(seed *domain.Seed, seedOnly bool) {
	distilledProg := new(prog.Prog)
	distilledProg.Calls = make([]*prog.Call, 0)
	callIndexes := make([]int, 0)
	totalCalls := make([]*prog.Call, 0)

	if d.CallToDistilledProg[seed.Call] != nil {
		return  /* skip call if already in a distilled program */
	}
	seenMap := make(map[int]bool, 0)
	upstreamCalls := make([]*prog.Call, 0)
	/* collect list of all upstream dependent calls, unsorted? */
	upstreamCalls = append(upstreamCalls, d.GetAllUpstreamDependents(seed, seenMap)...)
	upstreamCalls = append(upstreamCalls, seed.Call) // add seed as last call
	upstreamCalls = d.AddImplicitDependencies(upstreamCalls, seed, seenMap, seedOnly)

	distinctProgs := d.getAllProgs(upstreamCalls)
	if len(distinctProgs) > 0 {  // we need to merge!
		// collect all the calls from all distinct progs, plus our upstreamCalls together
		totalCalls = append(d.getCalls(distinctProgs), upstreamCalls...)
	} else {
		totalCalls = upstreamCalls
	}

	callIndexes = d.uniqueCallIdxs(totalCalls)  // dedups and sorts calls by their program idx
	for _, idx := range callIndexes {
		call := seed.Prog.Calls[idx]
		d.CallToDistilledProg[call] = distilledProg  // set calls to point to new, merged program
		distilledProg.Calls = append(distilledProg.Calls, call)
	}
	d.BuildDependency(seed, distilledProg)  // set args to point to dependent args.
}

func syscallKeyword(syscall string) string {
	return strings.Split(syscall, "$")[0]
}

func (d *ImplicitDistiller) AddImplicitDependencies(
	calls []*prog.Call,
	seed *domain.Seed,
	seenMap map[int]bool,
	seedOnly bool,
) []*prog.Call {
	implicit_callmap := make(map[string]bool, 0)
	implicit_calls := make([]*prog.Call, 0)

	if seedOnly {  // get implicit deps of seed only
		if impl_deps, ok := d.impl_deps[syscallKeyword(seed.Call.Meta.Name)]; ok {
			for _, impl_dep := range impl_deps {
				implicit_callmap[impl_dep] = true
			}
		}
	} else {  // get implicit deps of seed + upstream explicit deps
		for _, call := range calls {
			impl_deps, ok := d.impl_deps[syscallKeyword(call.Meta.Name)]
			if !ok {
				//fmt.Fprintf(os.Stderr, "no implicit dependencies for %s\n", call.Meta.Name)
				continue
			}
			for _, impl_dep := range impl_deps {
				implicit_callmap[impl_dep] = true
			}
		}
	}

	for i := 0; i < seed.CallIdx; i++ {
		if _, ok := implicit_callmap[syscallKeyword(seed.Prog.Calls[i].Meta.Name)]; ok {
			//fmt.Fprintf(os.Stderr, "Adding implicit call %s\n", seed.Prog.Calls[i].Meta.Name)
			implicit_calls = append(implicit_calls, seed.Prog.Calls[i])
		}
	}

	// add all (explicit) upstream dependents of implicit_calls
	upstreamOfImplCalls := make([]*prog.Call, 0)
	for _, impl_call := range implicit_calls {
		if s, ok := d.CallToSeed[impl_call]; ok {
			upstreamOfImplCalls = append(
				upstreamOfImplCalls,
				d.GetAllUpstreamDependents(s, seenMap)...,
			)
		}
	}
	calls = append(calls, upstreamOfImplCalls...)
	return calls
}
