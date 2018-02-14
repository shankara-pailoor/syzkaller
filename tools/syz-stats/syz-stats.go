package main

import (
	"bufio"
	"encoding/json"
	"flag"
	"fmt"
	"github.com/Sirupsen/logrus"
	"github.com/google/syzkaller/pkg/rpctype"
	"github.com/google/syzkaller/pkg/symbolizer"
	"github.com/google/syzkaller/pkg/cover"
	sparser "github.com/mattrco/difftrace/parser"
	"os"
	"os/exec"
	"strings"
	"strconv"
	"bytes"
	"path"
	"io/ioutil"
)

var (
	corpuses = flag.String("corpuses", "", "Path to file containing corpuses")
	traces = flag.String("traces", "", "Path to directory containing traces")
	vmlinux = flag.String("vmlinux", "", "Path to vmlinux e.g. linux-4.14-rc1/vmlinux")
	decode = flag.String("decode", "", "Decode instructions from trace")
	aggregate = flag.Bool("aggregate", false, "Aggregate statistics from traces or corpuses")
)

const (
	callLen = 5
	COVER_ID    = "Cover:"
	COVER_DELIM = ","
)

type Corpus struct {
	Name string
	Data map[string]rpctype.RpcInput
}

type CorpusStats struct {
	CorpusName string
	SyscallCover map[string][]uint64
	FileCover map[string][]uint64
	SubsystemCover map[string][]uint64
	TotalCoverage int
}

func Merge(cs []*CorpusStats) (c *CorpusStats) {
	c = new(CorpusStats)
	c.CorpusName = "Aggregate"
	c.SyscallCover = make(map[string][]uint64)
	c.FileCover = make(map[string][]uint64)
	c.SubsystemCover = make(map[string][]uint64)

	callCoverMap := make(map[string]map[uint64]bool)
	fileCoverMap := make(map[string]map[uint64]bool)
	subsystemCoverMap := make(map[string]map[uint64]bool)
	insMap := make(map[uint64]bool)
	for _, corpusStat := range cs {
		for call, coverage := range corpusStat.SyscallCover {
			if _, ok := callCoverMap[call]; !ok {
				callCoverMap[call] = make(map[uint64]bool)
			}
			for _, ip := range coverage {
				if _, ok := insMap[ip]; !ok {
					insMap[ip] = true
				}
				if _, ok := callCoverMap[call][ip]; !ok {
					callCoverMap[call][ip] = true
				}
			}
		}

		for call, coverage := range corpusStat.FileCover {
			if _, ok := fileCoverMap[call]; !ok {
				fileCoverMap[call] = make(map[uint64]bool)
			}
			for _, ip := range coverage {
				if _, ok := fileCoverMap[call][ip]; !ok {
					fileCoverMap[call][ip] = true
				}
			}
		}

		for call, coverage := range corpusStat.SubsystemCover {
			if _, ok := subsystemCoverMap[call]; !ok {
				subsystemCoverMap[call] = make(map[uint64]bool)
			}
			for _, ip := range coverage {
				if _, ok := subsystemCoverMap[call][ip]; !ok {
					subsystemCoverMap[call][ip] = true
				}
			}
		}
	}

	for call, ips := range callCoverMap {
		if _, ok := c.SyscallCover[call]; !ok {
			c.SyscallCover[call] = make([]uint64, 0)
		}
		for ip, _ := range ips {
			c.SyscallCover[call] = append(c.SyscallCover[call], ip)
		}
	}

	for call, ips := range fileCoverMap {
		if _, ok := c.FileCover[call]; !ok {
			c.FileCover[call] = make([]uint64, 0)
		}
		for ip, _ := range ips {
			c.FileCover[call] = append(c.FileCover[call], ip)
		}
	}

	for call, ips := range subsystemCoverMap {
		if _, ok := c.SubsystemCover[call]; !ok {
			c.SubsystemCover[call] = make([]uint64, 0)
		}
		for ip, _ := range ips {
			c.SubsystemCover[call] = append(c.SubsystemCover[call], ip)
		}
	}
	c.TotalCoverage = len(insMap)
	return
}

type ParsedFile struct {
	File string
	Subsystem string
	DirectoryBreakdown []string
}

func failf(msg string, args ...interface{}) {
	fmt.Fprintf(os.Stderr, msg+"\n", args...)
	os.Exit(1)
}

func main() {
	flag.Parse()
	corpusStats := make([]*CorpusStats, 0)
	traceStats := make([]*CorpusStats, 0)
	if *corpuses != "" {
		corpusStats = append(corpusStats, parseCorpuses(*corpuses, *vmlinux)...)
	}

	if *traces != "" {
		fmt.Printf("decode: %p\n", decode)
		if *decode != "" {
			decodeTraces(*traces, *decode, *vmlinux)
			return
		} else if *aggregate {
			traceStats = append(traceStats, parseTraces(*traces, *vmlinux)...)
			aggregatedStats := Merge(traceStats)
			computeCoverageBreakdown(aggregatedStats)
			return

		} else {
			traceStats = append(traceStats, parseTraces(*traces, *vmlinux)...)
		}
	}



	/*
	for _, input := range newestCorpus

		prg, err := prog.Deserialize(input.Prog)
		if err != nil {
			continue
		}
		args := make(map[*prog.Arg]string)
		trackProgDependencies(prg, args)
	}*/
	if len(corpusStats) == 1 {
		computeCoverageBreakdown(corpusStats[0])
	}
	if len(traceStats) == 1 {
		computeCoverageBreakdown(traceStats[0])
	}
	if len(traceStats) > 1  && len(corpusStats) == 1{
		aggregatedTraceStats := Merge(traceStats)
		computeCoverageDifference(aggregatedTraceStats, corpusStats[0])
		return

	}
	if len(traceStats) > 1 {
	    fmt.Printf("Trace Len: %d\n", len(traceStats))
		for i, traceStat := range traceStats {
            for _, traceStat2 := range traceStats[i+1:] {
                computeCoverageDifference(traceStat, traceStat2)
            }
        }
    }
	//fmt.Printf("CorpusStats: %v\n", corpusStats.SubsystemCover)
	for i, corpusStat := range corpusStats {
		for _, corpusStat2 := range corpusStats[i+1:] {
			computeCoverageDifference(corpusStat, corpusStat2)
		}
	}
}

func parseCorpuses(directory string, vmlinux string) []*CorpusStats{
	corpii := readCorpus(*corpuses)
	corpusStats := make([]*CorpusStats, 0)
	for _, corpus := range corpii {
		corpusStat := &CorpusStats {
			CorpusName: corpus.Name,
			SyscallCover: make(map[string][]uint64, 0),
			FileCover: make(map[string][]uint64, 0),
			SubsystemCover: make(map[string][]uint64, 0),
		}
		frames := ComputeFrames(vmlinux, corpus.Data)
		fmt.Printf("FRAME LEN: %d\n", len(frames))
		framePc := make(map[uint64][]symbolizer.Frame, 0)
		for _, frame := range frames {
			if _, ok := framePc[frame.PC]; !ok {
				framePc[frame.PC] = make([]symbolizer.Frame, 0)
			}
			framePc[frame.PC] = append(framePc[frame.PC], frame)
		}
		frames = make([]symbolizer.Frame, 0)
		for _, frames_ := range framePc {
			frames = append(frames, frames_[len(frames_)-1])
		}
		fmt.Printf("FRAME LENGTH: %d\n", len(framePc))
		fmt.Printf("Frame Length: %d\n", len(frames))

		if frames != nil {
			for _, frame := range frames {
				if _, ok := corpusStat.FileCover[frame.File]; !ok {
					corpusStat.FileCover[frame.File] = make([]uint64, 0)
				}
				corpusStat.FileCover[frame.File] = append(corpusStat.FileCover[frame.File], frame.PC)
				parsedFile := rebuildPath(frame.File)
				if _, ok := corpusStat.SubsystemCover[parsedFile.Subsystem]; !ok {
					corpusStat.SubsystemCover[parsedFile.Subsystem] = make([]uint64, 0)
				}
				corpusStat.SubsystemCover[parsedFile.Subsystem] = append(corpusStat.SubsystemCover[parsedFile.Subsystem], frame.PC)
				if _, ok := corpusStat.SyscallCover[frame.Func]; !ok {
					corpusStat.SyscallCover[frame.Func] = make([]uint64, 0)
				}
				corpusStat.SyscallCover[frame.Func] = append(corpusStat.SyscallCover[frame.Func], frame.PC)
			}
		}
		corpusStats = append(corpusStats, corpusStat)
	}

	return corpusStats
}


func decodeTraces(traceDir, decodeDir, vmlinux string) {
	symb := symbolizer.NewSymbolizer()
	defer symb.Close()


	traces := make([]string, 0)
	if fileInfos, err := ioutil.ReadDir(traceDir); err == nil {
		for _, fileInfo := range fileInfos {
			traces = append(traces, path.Join(traceDir, fileInfo.Name()))
		}
	}
	for _, t := range traces {
		decodedFile := path.Join(decodeDir, path.Base(t))
		calls := parseStrace(t)
		fmt.Printf("PARSE STRACE\n")
		f, err := os.OpenFile(decodedFile, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0644)
		if err != nil {
			failf(err.Error())
		}
		for _, call := range calls {
			coverMap := make(map[uint32]bool)
			coverArray := make([]uint32, 0)
			var buffer bytes.Buffer

			for _, ip := range call.Cover {
				ip_u32 := uint32(ip)
				if _, ok := coverMap[ip_u32]; !ok {
					coverMap[ip_u32] = true
				}
			}

			for ip, _ := range coverMap {
				coverArray = append(coverArray, ip)
			}

			frames := computeFrames(vmlinux, coverArray)
			header := fmt.Sprintf("SYSCALL: %s, pid: %d", call.FuncName,  call.Pid)
			buffer.Write([]byte(header))
			buffer.Write([]byte("\n"))

			for _, frame := range frames {
				frameData := fmt.Sprintf("Func: %s, File: %s, Line: %d\n", frame.Func, path.Base(frame.File), frame.Line)
				buffer.Write([]byte(frameData))
			}
			f.WriteString(buffer.String())
		}
	}
}

func parseTraces(traceDir string, vmlinux string) []*CorpusStats{
	traces := make([]string, 0)
	corpusStats := make([]*CorpusStats, 0)
	fmt.Printf("trace dir: %s\n", traceDir)
	if fileInfos, err := ioutil.ReadDir(traceDir); err == nil {
		for _, fileInfo := range fileInfos {
			traces = append(traces, path.Join(traceDir, fileInfo.Name()))
		}
	} else {
		failf("error reading directory: %s\n", err.Error())
	}
	for _, t := range traces {
		frameMap := make(map[uint64]symbolizer.Frame)
		syscallIps := make(map[string][]uint32)
		calls := parseStrace(t)
		for _, call := range calls {
			if _, ok := syscallIps[call.FuncName]; ok {
				syscallIps[call.FuncName] = make([]uint32, 0)
			}
			coverMap := make(map[uint32]bool)
			for _, ip := range call.Cover {
				ip_u32 := uint32(ip)
				if _, ok := coverMap[ip_u32]; !ok {
					coverMap[ip_u32] = true
					syscallIps[call.FuncName] = append(syscallIps[call.FuncName], ip_u32)
				}
				coverMap[ip_u32] = true
			}
		}
		corpusStat := &CorpusStats {
			CorpusName: t,
			SyscallCover: make(map[string][]uint64, 0),
			FileCover: make(map[string][]uint64, 0),
			SubsystemCover: make(map[string][]uint64, 0),
		}
		for call, ips := range syscallIps {
			frames := computeFrames(vmlinux, ips)

			if _, ok := corpusStat.SyscallCover[call]; !ok {
				corpusStat.SyscallCover[call] = make([]uint64, 0)
			}
			if _, ok := corpusStat.SyscallCover[call]; !ok {
				corpusStat.SyscallCover[call] = make([]uint64, 0)
			}
			for _, frame := range frames {
				if _, ok := frameMap[frame.PC]; !ok {
					frameMap[frame.PC] = frame
				}
				corpusStat.SyscallCover[call] = append(corpusStat.SyscallCover[call], frame.PC)
			}
		}
		for _, frame := range frameMap {
			if _, ok := corpusStat.FileCover[frame.File]; !ok {
				corpusStat.FileCover[frame.File] = make([]uint64, 0)
			}
			corpusStat.FileCover[frame.File] = append(corpusStat.FileCover[frame.File], frame.PC)
			parsedFile := rebuildPath(frame.File)
			if _, ok := corpusStat.SubsystemCover[parsedFile.Subsystem]; !ok {
				corpusStat.SubsystemCover[parsedFile.Subsystem] = make([]uint64, 0)
			}
			corpusStat.SubsystemCover[parsedFile.Subsystem] = append(corpusStat.SubsystemCover[parsedFile.Subsystem], frame.PC)
		}
		corpusStats = append(corpusStats, corpusStat)
	}
	return corpusStats
}

func computeCoverageBreakdown(stat *CorpusStats) {
	fmt.Printf("TOTAL COVERAGE: %d\n", stat.TotalCoverage)
	for subsystem, cov := range stat.SubsystemCover {
		seen := make(map[uint64]bool, 0)
		for _, ip := range cov {
			seen[ip] = true
		}
		fmt.Printf("Subsystem: %s, Seen: %d\n", subsystem, len(seen))
	}
	for syscall, cov := range stat.SyscallCover {
		seen := make(map[uint64]bool, 0)
		for _, ip := range cov {
			seen[ip] = true
		}
		fmt.Printf("System Call: %s, Seen: %d\n", syscall, len(seen))
	}
	for file, cov := range stat.FileCover {
		seen := make(map[uint64]bool, 0)
		for _, ip := range cov {
			seen[ip] = true
		}
		fmt.Printf("System Call: %s, Seen: %d\n", file, len(seen))
	}
}

func computeCoverageDifference(stat1, stat2 *CorpusStats) {
	totalSeen1 := make(map[uint64]bool, 0)
	totalSeen2 := make(map[uint64]bool, 0)
	totalSeenIn2Not1 := make(map[uint64]bool, 0)
	totalSeenIn1Not2 := make(map[uint64]bool, 0)
	totalSeenInBoth := make(map[uint64]bool, 0)
	for _, cov := range stat1.SubsystemCover {
		for _, ip := range cov {
			totalSeen1[ip] = true
		}
	}
	for _, cov := range stat2.SubsystemCover {
		for _, ip := range cov {
			totalSeen2[ip] = true
			if _, ok := totalSeen1[ip]; !ok {
				totalSeenIn2Not1[ip] = true
			} else {
				totalSeenInBoth[ip] = true
			}
		}
	}
	for _, cov := range stat1.SubsystemCover {
		for _, ip := range cov {
			if _, ok := totalSeen2[ip]; !ok {
				totalSeenIn1Not2[ip] = true
			}
		}
	}
	fmt.Printf("Coverage Difference between: %s and %s\n", stat1.CorpusName, stat2.CorpusName)
	fmt.Printf("Seen In Both: %d, Seen Only In 1: %d, Seen Only In 2: %d\n", len(totalSeenInBoth), len(totalSeenIn1Not2), len(totalSeenIn2Not1))
	for stat1Subsystem, cov := range stat1.SubsystemCover {
		if cov1, ok := stat2.SubsystemCover[stat1Subsystem]; ok {
			seen1 := make(map[uint64]bool, 0)
			seen2 := make(map[uint64]bool, 0)
			seenIn2Not1 := make(map[uint64]bool, 0)
			seenIn1Not2 := make(map[uint64]bool, 0)
			seenInBoth := make(map[uint64]bool, 0)
			for _, ip := range cov {
				seen1[ip] = true
			}
			for _, ip := range cov1 {
				if _, ok := seen1[ip]; !ok {
					seenIn2Not1[ip] = true
				} else {
					seenInBoth[ip] = true
				}
				seen2[ip] = true
			}
			for _, ip := range cov {
				if _, ok := seen2[ip]; !ok {
					seenIn1Not2[ip] = true
				} else {
					seenInBoth[ip] = true
				}
			}
			if len(seenIn1Not2) == 0 && len(seenIn2Not1) == 0 {
				if len(seenInBoth) > 0 {
					fmt.Printf("Subsystem: %s, SeenInBoth: %d\n", stat1Subsystem, len(seenInBoth))
				}
				continue
			}
			fmt.Printf("Subsystem: %s, Num Blocks Seen Only In %s: %d, Num Seen Only In %s: %d, Num Seen In Both: %d\n", stat1Subsystem, stat1.CorpusName, len(seenIn1Not2), stat2.CorpusName, len(seenIn2Not1), len(seenInBoth))
		} else {
			seen1 := make(map[uint64]bool, 0)
			for _, ip := range cov {
				seen1[ip] = true
			}
			fmt.Printf("Subsystem: %s, Num Blocks Seen Only In %s: %d\n", stat1Subsystem, stat1.CorpusName, len(seen1))
		}
	}
	for stat1File, cov := range stat1.FileCover {
		if cov1, ok := stat2.FileCover[stat1File]; ok {
			seen1 := make(map[uint64]bool, 0)
			seen2 := make(map[uint64]bool, 0)
			seenIn2Not1 := make(map[uint64]bool, 0)
			seenIn1Not2 := make(map[uint64]bool, 0)
			seenInBoth := make(map[uint64]bool, 0)
			for _, ip := range cov {
				seen1[ip] = true
			}
			for _, ip := range cov1 {
				if _, ok := seen1[ip]; !ok {
					seenIn2Not1[ip] = true
				} else {
					seenInBoth[ip] = true
				}
				seen2[ip] = true
			}
			for _, ip := range cov {
				if _, ok := seen2[ip]; !ok {
					seenIn1Not2[ip] = true
				} else {
					seenInBoth[ip] = true
				}
			}
			if len(seenIn1Not2) == 0 && len(seenIn2Not1) == 0 {
				if len(seenInBoth) > 0 {
					fmt.Printf("File: %s, SeenInBoth: %d\n", stat1File, len(seenInBoth))
				}
				continue
			}
			fmt.Printf("File: %s, SeenInOnly %s: %d, SeenInOnly %s: %d, SeenInBoth: %d\n", stat1File, stat1.CorpusName, len(seenIn1Not2), stat2.CorpusName, len(seenIn2Not1), len(seenInBoth))
		}
	}
}

func rebuildPath(path string) *ParsedFile {
	parsedFile := new(ParsedFile)
	splitPath := strings.Split(path, "/")
	if len(splitPath) > 3 {
		splitPath = splitPath[4:]
	}
	parsedFile.File = path
	if splitPath[0] == "kernel" {
		if strings.Contains(splitPath[1], ".c") {
			parsedFile.Subsystem = "kernel"
		} else {
			parsedFile.Subsystem = splitPath[1]
		}
	} else {
		if splitPath[0] == "." {
			parsedFile.Subsystem = splitPath[1]
		} else {
			parsedFile.Subsystem = splitPath[0]
		}
	}
	return parsedFile
}

func ComputeFrames(vmlinux string, data map[string]rpctype.RpcInput) []symbolizer.Frame {
	coverMap := make(map[uint32]bool, 0)
	coverArray := make([]uint32, 0)

	for _, inp := range data {
		for _, cov := range inp.Cover {
			if _, ok := coverMap[cov]; !ok {
				coverMap[cov] = true
			}
		}
	}
	for ip, _ := range coverMap {
		coverArray = append(coverArray, ip)
	}

	return computeFrames(vmlinux, coverArray)
}

func computeFrames(vmlinux string, coverArray []uint32) []symbolizer.Frame {
	base, err := getVmOffset(vmlinux)
	if err != nil {
		fmt.Printf("Error: %s\n", err.Error())
		panic("Failure")
	}
	pcs := make([]uint64, len(coverArray))

	for i, pc := range coverArray {
		pcs[i] = cover.RestorePC(pc, base) - callLen
	}

	coveredFrames, _, err := symbolize(vmlinux, pcs)
	if err != nil {
		fmt.Printf("Covered Frames: %s\n", err.Error())
		return nil
	}
	if len(coveredFrames) == 0 {
		fmt.Errorf("'%s' does not have debug info (set CONFIG_DEBUG_INFO=y)", vmlinux)
		return nil
	}
	return coveredFrames

}

func symbolize(vmlinux string, pcs []uint64) ([]symbolizer.Frame, string, error) {
	symb := symbolizer.NewSymbolizer()
	defer symb.Close()

	frames, err := symb.SymbolizeArray(vmlinux, pcs)
	if err != nil {
		return nil, "", err
	}

	prefix := ""
	for i := range frames {
		frame := &frames[i]
		frame.PC--
		if prefix == "" {
			prefix = frame.File
		} else {
			i := 0
			for ; i < len(prefix) && i < len(frame.File); i++ {
				if prefix[i] != frame.File[i] {
					break
				}
			}
			prefix = prefix[:i]
		}

	}
	return frames, prefix, nil
}

func getVmOffset(vmlinux string) (uint32, error) {
	out, err := exec.Command("readelf", "-SW", vmlinux).CombinedOutput()
	if err != nil {
		return 0, fmt.Errorf("readelf failed: %v\n%s", err, out)
	}
	s := bufio.NewScanner(bytes.NewReader(out))
	var addr uint32
	for s.Scan() {
		ln := s.Text()
		pieces := strings.Fields(ln)
		for i := 0; i < len(pieces); i++ {
			if pieces[i] != "PROGBITS" {
				continue
			}
			v, err := strconv.ParseUint("0x"+pieces[i+1], 0, 64)
			if err != nil {
				return 0, fmt.Errorf("failed to parse addr in readelf output: %v", err)
			}
			if v == 0 {
				continue
			}
			v32 := (uint32)(v >> 32)
			if addr == 0 {
				addr = v32
			}
			if addr != v32 {
				return 0, fmt.Errorf("different section offsets in a single binary")
			}
		}
	}
	return addr, nil
}

func parseStrace(filename string) (calls []*sparser.OutputLine) {
	var lastParsed *sparser.OutputLine
	calls = make([]*sparser.OutputLine, 0)
	f, err := os.Open(filename)
	if err != nil {
		fmt.Printf("failed to open file: %v\n", filename)
		failf(err.Error())
	}
	p := sparser.NewParser(f)
	i := 0
	for {
		line, err := p.Parse()
		if err != nil {
			if err != sparser.ErrEOF {
				fmt.Println("sparser error: %s", err.Error())
			}
			return
		}
		if line == nil {
			continue
		}
		if line.FuncName == "" && line.Result != "" && !line.Paused && !line.Resumed {
			if lastParsed == nil {
				continue
			}
			lastParsed.Cover = parseInstructions(line.Result)
		} else {
			//if _, ok := Unsupported[line.FuncName]; ok {
			//	lastParsed = nil
			//	continue
			//}
			lastParsed = line
			calls = append(calls, line)
		}
		i += 1
		fmt.Printf("I: %d\n", i)
	}
	return
}

func parseInstructions(line string) (ips []uint64) {
	/* function returns a slice of all unique IPs hit by this call
	 Used to popoulate field Seed.Cover
	*/
	uniqueIps := make(map[uint64]bool)
	line = line[1: len(line)-1]
	strippedLine := strings.TrimSpace(line)
	/*
		Instructions for a call all appear in one line of the form
		COVER_IDip1COVER_DELIMip2COVER_DELIMip3. Ex: If COVER_ID = "Cover:" and
		COVER_DELIM = "-" then it would appear as "Cover:ip1-ip2-ip3"

	*/
	instructions := strings.Split(strippedLine, COVER_ID)
	s := strings.Split(instructions[1], COVER_DELIM)
	for _, ins := range s {
		if ins == "" {
			continue
		}
		ip, err := strconv.ParseUint(strings.TrimSpace(ins), 0, 64)
		if err != nil {
			failf("failed parsing ip: %s", ins)
		}
		if _, ok := uniqueIps[ip]; !ok {
			uniqueIps[ip] = true
			ips = append(ips, ip)
		}
	}
	return
}


func readCorpus(directory string) ([]*Corpus) {
	corpii := make([]*Corpus, 0)
	fileInfos, err := ioutil.ReadDir(directory)
	if err != nil {
		fmt.Printf("Error: %s\n", err.Error())
	}
	for _, fileInfo := range fileInfos {
		data := make([]map[string]rpctype.RpcInput, 0)
		f, err := os.Open(path.Join(directory, fileInfo.Name()))
		if err != nil {
			logrus.Fatalf("failed to open input file: %v", err)
		}
		defer f.Close()
		dec := json.NewDecoder(bufio.NewReader(f))
		for dec.More() {
			v := make(map[string]rpctype.RpcInput)
			if err := dec.Decode(&v); err != nil {
				logrus.Fatalf("failed to decode input file %v: %v", fileInfo.Name(), err)
			}
			data = append(data, v)
		}
		corpus := &Corpus {
			Name: fileInfo.Name(),
			Data: data[len(data)-1],
		}
		corpii = append(corpii, corpus)
	}
	return corpii
}

