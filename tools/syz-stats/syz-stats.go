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
	"path"
	"io/ioutil"
)

var (
	corpuses = flag.String("corpuses", "", "Path to file containing corpuses")
)

const (
	callLen = 5
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
	corpusStats := make([]*CorpusStats, 0)
	for _, corpus := range corpii {
		corpusStat := &CorpusStats {
			CorpusName: corpus.Name,
			SyscallCover: make(map[string][]uint64, 0),
			FileCover: make(map[string][]uint64, 0),
			SubsystemCover: make(map[string][]uint64, 0),
		}
		frames := ComputeFrames("/home/w4118/linux-4.10-rc7/vmlinux", corpus.Data)
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

	//fmt.Printf("CorpusStats: %v\n", corpusStats.SubsystemCover)
	for i, corpusStat := range corpusStats {
		for _, corpusStat2 := range corpusStats[i:] {
			computeSubsystemDifference(corpusStat, corpusStat2)
		}
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

func computeSubsystemDifference(stat1, stat2 *CorpusStats) {
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
	}}

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

	for cov, _ := range coverMap {
		coverArray = append(coverArray, cov)
	}
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
