package distiller

import (
	"github.com/google/syzkaller/tools/syz-strace/domain"
	"github.com/google/syzkaller/prog"
	"github.com/google/syzkaller/tools/syz-strace/implicit-dependencies"
	"fmt"
	"sort"
	"os"
	"strings"
	"math/rand"
	"time"
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

func (d *ImplicitDistiller) getHeavyHitters(seeds domain.Seeds) domain.Seeds {
	seenIps := make(map[uint64]bool)
	heavyHitters := make(domain.Seeds, 0)
	contributing_seeds := 0
	for _, seed := range seeds {
		ips := d.Contributes(seed, seenIps)  /* how many unique Ips does seed contribute */
		if ips > 0 {
			heavyHitters.Add(seed)
			fmt.Printf("Seed: %s contributes: %d ips out of its total of: %d\n", seed.Call.Meta.Name, ips, len(seed.Cover))
			contributing_seeds += 1
		}
	}
	return heavyHitters
}

func (d *ImplicitDistiller) getRandomSeeds(seeds domain.Seeds) domain.Seeds {
	heavyHitters := d.getHeavyHitters(seeds)
	randHitters := make(domain.Seeds, 0)
	totalCalls := len(seeds)
	rand.Seed(time.Now().Unix())
	for i:=0; i < len(heavyHitters); i++ {
		idx := rand.Int31n(int32(totalCalls))
		randHitters.Add(seeds[idx])
	}
	return randHitters
}

func (d *ImplicitDistiller) Distill(progs []*prog.Prog) (distilled []*prog.Prog) {
	seeds := d.Seeds
	fmt.Printf("Performing implicit distillation with %d seeds\n", len(seeds))
	sort.Sort(sort.Reverse(seeds))  // sort seeds by inidividual coverage.
	heavyHitters := make(domain.Seeds, 0)
	for _, prog := range progs {
		d.TrackDependencies(prog)
	}
	heavyHitters = d.getHeavyHitters(seeds)
	for _, seed := range heavyHitters {
		d.AddToDistilledProg(seed)
	}
	distilledProgs := make(map[*prog.Prog]bool)
	for _, seed := range seeds {
		if _, ok := d.CallToDistilledProg[seed.Call]; ok {
			distilledProgs[d.CallToDistilledProg[seed.Call]] = true
		}
	}
	for prog_, _ := range distilledProgs {
		if err := d.CallToSeed[prog_.Calls[0]].State.Tracker.FillOutMemory(prog_); err != nil {
			fmt.Printf("Error: %s\n", err.Error())
			continue
		}
		totalMemoryAllocations := d.CallToSeed[prog_.Calls[0]].State.Tracker.GetTotalMemoryAllocations(prog_)
		state := d.CallToSeed[prog_.Calls[0]].State
		mmapCall := state.Target.MakeMmap(0, uint64(totalMemoryAllocations/pageSize)+1)
		calls := make([]*prog.Call, 0)
		calls = append(append(calls, mmapCall), prog_.Calls...)

		prog_.Calls = calls

		distilled = append(distilled, prog_)
	}
	avgLen := 0
	progs_ := 0
	for _, prog_ := range distilled {
		if len(prog_.Calls) < 2 {
			continue
		}
		progs_ += 1
		avgLen += len(prog_.Calls)
	}
	avgLen /= progs_
	fmt.Fprintf(os.Stderr, "Average Program Length: %d\n", avgLen)
	fmt.Fprintf(os.Stderr,
		"Total Contributing seeds: %d out of %d, in %d implicitly-distilled programs\n",
		len(heavyHitters), len(seeds), len(distilled),
	)
	return
}

func (d *ImplicitDistiller) AddToDistilledProg(seed *domain.Seed) {
	distilledProg := new(prog.Prog)
	distilledProg.Calls = make([]*prog.Call, 0)
	callIndexes := make([]int, 0)
	totalCalls := make([]*prog.Call, 0)

	if d.CallToDistilledProg[seed.Call] != nil {
		return  /* skip call if already in a distilled program */
	}
	seenMap := make(map[int]bool, 0)
	upstreamCalls := make([]*prog.Call, 0)

	upstreamCalls = append(upstreamCalls, d.GetAllUpstreamDependents(seed, seenMap)...)
	upstreamCalls = append(upstreamCalls, seed.Call) // add seed as last call
	upstreamCalls = d.AddImplicitDependencies(upstreamCalls, seed, seenMap)

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

func dedupSyscalls(calls []*prog.Call) []*prog.Call {
	seenCalls := make(map[*prog.Call]bool, 0)
	ret := make([]*prog.Call, 0)

	for _, call := range calls {
		if _, ok := seenCalls[call]; !ok {
			seenCalls[call] = true
			ret = append(ret, call)
		}
	}
	return ret
}

func (d *ImplicitDistiller) AddImplicitDependencies(
	calls []*prog.Call,
	seed *domain.Seed,
	seenMap map[int]bool,
) []*prog.Call {
	/* Recursively collect implicit --> explicit --> implicit ... dependencies */
	implicit_callmap := make(map[string]bool, 0)
	implicit_calls := make([]*prog.Call, 0)
	orig_call_len := len(dedupSyscalls(calls))

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
	calls = dedupSyscalls(calls)
	if len(calls) > orig_call_len {
		// if we added more calls, need to recursively readd implicit deps of these new calls
		return d.AddImplicitDependencies(calls, seed, seenMap)
	}
	return calls
}
