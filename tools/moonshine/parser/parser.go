package parser

import (
	"fmt"
	"io/ioutil"
	"bufio"
	"strings"
	"github.com/google/syzkaller/tools/moonshine/types"
	//"github.com/cznic/golex/lex"
	"strconv"
)

const(
	maxBufferSize = 64*1024*1024
	CoverDelim = ","
	CoverID = "Cover:"
)

func parseIps(line string) []uint64 {
	line = line[1: len(line)-1] //Remove quotes
	ips := strings.Split(strings.Split(line, CoverID)[1], CoverDelim)
	cover_set := make(map[uint64]bool, 0)
	cover := make([]uint64, 0)
	for _, ins := range ips {
		if ins == "" {
			continue
		} else {
			ip, err := strconv.ParseUint(strings.TrimSpace(ins), 0, 64)
			if err != nil {
				panic(fmt.Sprintf("failed parsing ip: %s", ins))
			}
			if _, ok := cover_set[ip]; !ok {
				cover_set[ip] = true
				cover = append(cover, ip)
			}
		}
	}
	return cover
}

func parseLoop(scanner *bufio.Scanner) (tree *types.TraceTree) {
	var cover []uint64 = nil
	tree = types.NewTraceTree()
	//Creating the process tree
	for scanner.Scan() {
		line := scanner.Text()
		if strings.Contains(line, CoverID) {
			cover = parseIps(line)
			fmt.Printf("Cover: %d\n", len(cover))
			continue
		} else {
			lex := newLexer(scanner.Bytes())
			StraceParse(lex)
			call := lex.result
			if cover != nil {
				call.Cover = cover
			}
			tree.Add(call)
			//trace.Calls = append(trace.Calls, call)
			fmt.Printf("result: %v\n", lex.result.CallName)
		}

	}
	return nil
}

func Parse(filename string) {
	var data []byte
	var err error

	if data, err = ioutil.ReadFile(filename); err != nil {
		panic(fmt.Sprintf("error reading file: %s\n", err.Error()))
	}
	buf := make([]byte, maxBufferSize)
	scanner := bufio.NewScanner(strings.NewReader(string(data)))
	scanner.Buffer(buf, maxBufferSize)

	parseLoop(scanner)
}
