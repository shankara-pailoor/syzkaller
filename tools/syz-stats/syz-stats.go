package main

import (
	"bufio"
	"encoding/json"
	"flag"
	"fmt"
	"github.com/Sirupsen/logrus"
	"github.com/google/syzkaller/rpctype"
	"github.com/google/syzkaller/symbolizer"
	"github.com/google/syzkaller/cover"
	"os"
	"os/exec"
	"strings"
	"strconv"
	"bytes"
)

var (
	corpuses = flag.String("corpuses", "", "Path to file containing corpuses")
)

const (
	callLen = 5
)

type CorpusStats struct {
	SyscallCover map[string][]uint64
	FileCover map[string][]uint64
	SubsystemCover map[string][]uint64
}

type ParsedFile struct {
	File string
	Subsystem string
	DirectoryBreakdown []string
}


func main() {
	flag.Parse()
	if corpuses == nil {
		logrus.Infof("")
	}
	corpii := readCorpus(*corpuses)
	corpusStats := &CorpusStats {
		SyscallCover: make(map[string][]uint64, 0),
		FileCover: make(map[string][]uint64, 0),
		SubsystemCover: make(map[string][]uint64, 0),
	}
	newestCorpus := corpii[len(corpii)-1]
	frames := ComputeFrames("/home/w4118/linux-4.10-rc7/vmlinux", newestCorpus)
	if frames != nil {
		for _, frame := range frames {
			if _, ok := corpusStats.FileCover[frame.File]; !ok {
				corpusStats.FileCover[frame.File] = make([]uint64, 0)
			}
			corpusStats.FileCover[frame.File] = append(corpusStats.FileCover[frame.File], frame.PC)
			parsedFile := rebuildPath(frame.File)
			if _, ok := corpusStats.SubsystemCover[parsedFile.Subsystem]; !ok {
				corpusStats.SubsystemCover[parsedFile.Subsystem] = make([]uint64, 0)
			}
			corpusStats.SubsystemCover[parsedFile.Subsystem] = append(corpusStats.SubsystemCover[parsedFile.Subsystem], frame.PC)
			if _, ok := corpusStats.SyscallCover[frame.Func]; !ok {
				corpusStats.SyscallCover[frame.Func] = make([]uint64, 0)
			}
			corpusStats.SyscallCover[frame.Func] = append(corpusStats.SyscallCover[frame.Func], frame.PC)
		}
	}
	//fmt.Printf("CorpusStats: %v\n", corpusStats.SubsystemCover)
	for subsystem, cov := range corpusStats.SubsystemCover {
		fmt.Printf("Subsystem: %s, CoverageLen: %d\n", subsystem, len(cov))
	}
	for file, cov := range corpusStats.FileCover {
		fmt.Printf("File: %s, CoverageLen: %d\n", file, len(cov))
	}
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
	var totalCover int = 0
	for cov, _ := range coverMap {
		totalCover += 1
		coverArray = append(coverArray, cov)
	}
	fmt.Printf("TOTAL COVERAGE: %d\n", totalCover)
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
