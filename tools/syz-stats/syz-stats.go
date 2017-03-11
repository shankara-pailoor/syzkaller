package main

import (
	"bufio"
	"encoding/json"
	"flag"
	"fmt"
	"github.com/Sirupsen/logrus"
	"github.com/google/syzkaller/prog"
	"github.com/google/syzkaller/rpctype"
	"os"

	"sort"
	"strconv"
)

var (
	corpuses = flag.String("corpuses", "", "Path to file containing corpuses")
)

type ThresholdSummary struct {
	NumHitters           int
	CoverageContribution int
	AvgProgramLen        float32
}

type CallGraph struct {
	Name      string
	Neighbors map[string]*CallGraph
}

func main() {
	flag.Parse()
	if corpuses == nil {
		logrus.Infof("")
	}
	corpii := readCorpus(*corpuses)
	newestCorpus := corpii[len(corpii)-1]
	countHeavyHitters(newestCorpus, []int{100, 200, 300, 400, 500, 600, 700, 800, 900, 1000})

	/*
	for _, input := range newestCorpus {

		prg, err := prog.Deserialize(input.Prog)
		if err != nil {
			continue
		}
		args := make(map[*prog.Arg]string)
		trackProgDependencies(prg, args)
	}*/
}

func trackProgDependencies(prg *prog.Prog, args map[*prog.Arg]string) {
	callGraph := make(map[string]*CallGraph)
	for i, call := range prg.Calls {
		callId := call.Meta.Name + "-" + strconv.FormatInt(int64(i), 10)
		if _, ok := callGraph[callId]; !ok {
			callGraph[callId] = new(CallGraph)
			callGraph[callId].Name = callId
			callGraph[callId].Neighbors = make(map[string]*CallGraph)
		}
		for _, arg := range call.Args {
			//fmt.Printf("Arg: %s, %v\n", call.Meta.CallName, arg)
			upstream_maps := isDependent(arg, callId, args)
			for k, _ := range upstream_maps {
				callGraph[k].Neighbors[callId] = callGraph[callId]
				callGraph[callId].Neighbors[callGraph[k].Name] = callGraph[k]
			}
		}
		args[call.Ret] = callId
	}
	seen := make(map[string]bool)
	for id, gr := range callGraph {
		if _, ok := seen[id]; !ok {
			printGraph(gr, seen)
		}

		fmt.Printf("\n\n\n\n###################\n")
	}
	fmt.Printf("%s\n", string(prg.Serialize()))
}

func printGraph(graph *CallGraph, seen map[string]bool) {
	fmt.Printf("%s-", graph.Name)
	for name, node := range graph.Neighbors {
		if _, ok := seen[name]; !ok {
			seen[name] = true
			printGraph(node, seen)
		}
	}
	seen[graph.Name] = true
}

func isDependent(arg *prog.Arg, callId string, args map[*prog.Arg]string) map[string]bool {
	upstreamSet := make(map[string]bool, 0)
	if arg == nil {
		return nil
	}
	//May need to support more kinds
	switch arg.Kind {
	case prog.ArgResult:
		//fmt.Printf("%v\n", args[arg.Res])
		if _, ok := args[arg.Res]; ok {
			fmt.Printf("%s\n", callId)
			upstreamSet[args[arg.Res]] = true
		}
	case prog.ArgPointer:
		if _, ok := args[arg.Res]; ok {
			upstreamSet[args[arg.Res]] = true
		} else {
			for k, _ := range isDependent(arg.Res, callId, args) {
				upstreamSet[k] = true
			}
		}

	case prog.ArgGroup:
		for _, inner_arg := range arg.Inner {
			innerArgMap := isDependent(inner_arg, callId, args)
			for k, _ := range innerArgMap {
				upstreamSet[k] = true
			}
		}

	}
	args[arg] = callId
	//doesn't hurt to add again if it was already added
	return upstreamSet
}

func readCorpus(fname string) (data []map[string]rpctype.RpcInput) {
	f, err := os.Open(fname)
	if err != nil {
		logrus.Fatalf("failed to open input file: %v", err)
	}
	defer f.Close()
	dec := json.NewDecoder(bufio.NewReader(f))
	for dec.More() {
		v := make(map[string]rpctype.RpcInput)
		if err := dec.Decode(&v); err != nil {
			logrus.Fatalf("failed to decode input file %v: %v", fname, err)
		}
		data = append(data, v)
	}
	return
}

func countHeavyHitters(corpus map[string]rpctype.RpcInput, thresholds []int) {
	seenPCs := make(map[uint32]bool)
	seenPrograms := make(map[string]bool)
	coverMap := make(map[int][]string)
	coverArray := make([]int, 0)
	numPrograms := 0
	thresholdStats := make([]ThresholdSummary, len(thresholds))
	coverageTotal := 0

	sort.Ints(thresholds)
	for k, v := range corpus {
		if _, ok := seenPrograms[k]; !ok {
			coverArray = append(coverArray, len(v.Cover))
			if _, kk := coverMap[len(v.Cover)]; !kk {
				coverMap[len(v.Cover)] = make([]string, 0)
				coverMap[len(v.Cover)] = append(coverMap[len(v.Cover)], k)
			}

		}
	}
	sort.Sort(sort.Reverse(sort.IntSlice(coverArray)))

	for _, k := range coverArray {
		for _, program := range coverMap[k] {
			unique_pc := 0
			rpcinput := corpus[program]
			prg, err := prog.Deserialize(rpcinput.Prog)
			if err != nil {
				logrus.Errorf("Error: %s\n", err.Error())
			}
			for _, pc := range rpcinput.Cover {
				if _, ok := seenPCs[pc]; !ok {
					unique_pc += 1
					seenPCs[pc] = true
				}
			}
			for i, t := range thresholds {
				if unique_pc >= t {
					thresholdStats[i].CoverageContribution += unique_pc
					thresholdStats[i].NumHitters += 1
					thresholdStats[i].AvgProgramLen += (float32(len(prg.Calls)) - float32(thresholdStats[i].AvgProgramLen)) / float32(thresholdStats[i].NumHitters)
				}
			}
			coverageTotal += unique_pc
			numPrograms += 1
		}
	}
	fmt.Printf("Total programs: %d, Total Covered: %d\n", numPrograms, coverageTotal)
	for i := 0; i < len(thresholds); i++ {
		fmt.Printf("Threshold: %d, Num Programs: %d, Coverage: %d, Average Len: %f\n", thresholds[i], thresholdStats[i].NumHitters, thresholdStats[i].CoverageContribution, thresholdStats[i].AvgProgramLen)
	}
}
