package distiller

import (
	"github.com/google/syzkaller/prog"
	"fmt"
	"sort"
	"github.com/google/syzkaller/tools/syz-strace/domain"
	"github.com/google/syzkaller/sys"
	"os"
)

type DistillerMetadata struct {
	StatFile string
	Seeds domain.Seeds
	DistilledProgs []*prog.Prog
	CallToSeed map[*prog.Call]*domain.Seed
	CallToDistilledProg map[*prog.Call]*prog.Prog
	CallToIdx map[*prog.Call]int
	UpstreamDependencyGraph map[*domain.Seed]map[int]map[*prog.Arg][]*prog.Arg
	DownstreamDependents map[*domain.Seed]map[int]bool
}

func (d *DistillerMetadata) GetAllDownstreamDependents(seed *domain.Seed, seen map[int]bool) []*prog.Call {
	calls := make([]*prog.Call, 0)
	callMap := make(map[*prog.Call]bool, 0)
	fmt.Printf("Downstream: %s\n", seed.Call.Meta.CallName)
	for idx, _ := range d.DownstreamDependents[seed] {
		call := seed.Prog.Calls[idx]
		if seen[idx] || idx == seed.CallIdx {
			continue
		}
		seen[idx] = true
		if s, ok := d.CallToSeed[call]; ok {
			calls = append(calls, call)
			calls = append(calls, d.GetAllDownstreamDependents(s, seen)...)
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

func (d *DistillerMetadata) GetAllUpstreamDependents(seed *domain.Seed, seen map[int]bool) []*prog.Call {
	calls := make([]*prog.Call, 0)
	callMap := make(map[*prog.Call]bool, 0)
	for idx, _ := range d.UpstreamDependencyGraph[seed] {
		call := seed.Prog.Calls[idx]
		if seen[idx] || idx == seed.CallIdx {
			continue
		}
		seen[idx] = true
		if s, ok := d.CallToSeed[call]; ok {
			calls = append(calls, call)
			calls = append(calls, d.GetAllUpstreamDependents(s, seen)...)
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

func (d *DistillerMetadata) TrackDependencies(prg *prog.Prog) {
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
			fmt.Printf("Arg: %s, %v\n", call.Meta.CallName, arg)
			upstream_maps := d.isDependent(arg, seed, seed.State, i, args)
			for k, argMap := range upstream_maps {
				fmt.Printf("K: %d\n", k)
				if d.UpstreamDependencyGraph[seed][k] == nil {
					d.UpstreamDependencyGraph[seed][k] = make(map[*prog.Arg][]*prog.Arg, 0)
				}
				for argK, argVs := range argMap {
					//fmt.Printf("ARGVs: %v\n", argVs)
					d.UpstreamDependencyGraph[seed][k][argK] = append(d.UpstreamDependencyGraph[seed][k][argK], argVs...)
				}
			}
		}
		for idx, _ := range d.UpstreamDependencyGraph[seed] {
			if upstreamSeed, ok := d.CallToSeed[prg.Calls[idx]]; ok {
				if d.DownstreamDependents[upstreamSeed] == nil {
					d.DownstreamDependents[upstreamSeed] = make(map[int]bool, 0)
				}
				d.DownstreamDependents[upstreamSeed][i] = true
			}
		}
		fmt.Printf("depends on: %v\n", d.UpstreamDependencyGraph[seed])
		if call.Ret != nil {
			args[call.Ret] = i
			call.Ret.Uses = nil
		}
	}
}

func (d *DistillerMetadata) BuildDependency(seed *domain.Seed, distilledProg *prog.Prog) {
	for _, call := range distilledProg.Calls {
		if s, ok := d.CallToSeed[call]; ok {
			//fmt.Printf("HERE\n")
			dependencyMap := d.UpstreamDependencyGraph[s]
			for idx, argMap := range dependencyMap {
				upstreamSeed := d.CallToSeed[seed.Prog.Calls[idx]]
				for argK, argVs := range argMap {
					//fmt.Printf("dealing with argMap\n")
					for _, argV := range argVs {
						if _, ok := upstreamSeed.ArgMeta[argK]; !ok {
							fmt.Printf("UpstreamedSeed: %s, index: %d\n", upstreamSeed.Call.Meta.CallName, idx)
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
}

func (d *DistillerMetadata) Stats(distilledSeeds domain.Seeds) {
	totalCalls := d.Seeds.Len()
	distilledCalls := distilledSeeds.Len()
	if d.StatFile == "" {
		fmt.Printf("Total Calls: %d, Distilled: %d", totalCalls, distilledCalls)
	} else {
		f, err := os.OpenFile(d.StatFile, os.O_CREATE|os.O_APPEND|os.O_RDWR, 0600)
		if err != nil {
			fmt.Printf("Error opening stat file: %v\n", err.Error)
		}
		data := fmt.Sprintf("Total Calls: %d, Distilled: %d", totalCalls, distilledCalls)
		for _, seed := range distilledSeeds {
			data = fmt.Sprintf("Call: %s Contributes: %d\n", seed.Call.Meta.CallName, len(seed.Cover))
			f.WriteString(data)
		}
	}
}

func (d *DistillerMetadata) uniqueCallIdxs(calls []*prog.Call) []int {
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

func (d *DistillerMetadata) getAllProgs(calls []*prog.Call) (ret []*prog.Prog) {
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

func (d *DistillerMetadata) getCalls(progs []*prog.Prog) (ret []*prog.Call) {
	for _, p := range progs {
		ret = append(ret, p.Calls...)
	}
	return
}

func (d *DistillerMetadata) Contributes(seed *domain.Seed, seenIps map[uint64]bool) int {
	total := 0
	for _, ip := range seed.Cover {
		if _, ok := seenIps[ip]; !ok {
			seenIps[ip] = true
			total += 1
		}
	}
	return total
}

func (d *DistillerMetadata) isDependent(arg *prog.Arg, seed *domain.Seed, state *domain.State, callIdx int, args map[*prog.Arg]int) map[int]map[*prog.Arg][]*prog.Arg {
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
			for k, argMap := range d.isDependent(arg.Res, seed, state, callIdx, args) {
				if upstreamSet[k] == nil {
					upstreamSet[k] = make(map[*prog.Arg][]*prog.Arg, 0)
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
			if sys.IsPad(inner_arg.Type) {
				fmt.Printf("FOUND PAD for index: %d\n", callIdx)
			}
			for k, argMap := range d.isDependent(inner_arg, seed, state, callIdx, args) {
				if upstreamSet[k] == nil {
					upstreamSet[k] = make(map[*prog.Arg][]*prog.Arg, 0)
					upstreamSet[k] = argMap
				} else {
					for argK, argVs := range argMap {
						upstreamSet[k][argK] = append(upstreamSet[k][argK], argVs...)
					}
				}
			}
		}
	case prog.ArgUnion:
		if _, ok := args[arg.Res]; ok {
			dep := upstreamSet[args[arg.Res]][arg.Res]
			dep = append(dep, arg)
		} else {
			for k, argMap := range d.isDependent(arg.Option, seed, state, callIdx, args) {
				if upstreamSet[k] == nil {
					upstreamSet[k] = make(map[*prog.Arg][]*prog.Arg, 0)
					upstreamSet[k] = argMap
				} else {
					for argK, argVs := range argMap {
						upstreamSet[k][argK] = append(upstreamSet[k][argK], argVs...)
					}
				}
			}
		}
	case prog.ArgData:
		switch typ := arg.Type.(type) {
		case *sys.BufferType:
			if arg.Type.Dir() != sys.DirOut && arg.Kind == prog.ArgData && len(arg.Data) != 0 {
				switch typ.Kind {
				case sys.BufferFilename:
					callMap := make(map[*prog.Call]bool, 0)
					for s, calls := range state.Files {
						if s == string(arg.Data) {
							for _, call := range calls {
								if _, ok := callMap[call]; !ok {
									if d.CallToIdx[call] < seed.CallIdx {
										fmt.Printf("LESS THAN\n")
										d.UpstreamDependencyGraph[seed][d.CallToIdx[call]] = make(map[*prog.Arg][]*prog.Arg, 0)
										callMap[call] = true
									}
								}
							}
						}
					}
				}
			}
		}
	}
	args[arg] = callIdx
	arg.Uses = nil
	//doesn't hurt to add again if it was already added
	return upstreamSet
}