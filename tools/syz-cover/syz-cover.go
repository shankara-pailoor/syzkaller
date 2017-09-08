package main

import (
	"io/ioutil"
	"os"
	"os/exec"
	"github.com/Sirupsen/logrus"
	"encoding/json"
	"github.com/mattrco/difftrace/parser"
	"strings"
	"strconv"
	"golang.org/x/net/context"
	"cloud.google.com/go/storage"
	//"github.com/google/syzkaller/sys"
	"flag"
	"github.com/google/syzkaller/sys"
	"sort"
	"bytes"
	"runtime"
)

var (
	unsupported = map[int]bool {
		12: true, //brk
		21: true, //access
		22: true, //pipe
		31: true, //shmctl
		59: true, //execve
		72: true, //fctnl
		79: true, //getcwd
		80: true, //chdir
		96: true, //gettimeofday
		250: true, //keyctl
	}
)

type OverallCoverageStats struct {
	ValidSyscalls int
	ProgramStats []PerProgramStats
}

type PerProgramStats struct {
	UniqueIps int
	CallBreakdown []PerCallCoverage
}

type PerCallCoverage struct {
	SysNR int
	UniqueIps int
}

type WorkloadConfig struct {
	ExecutablePath string
	Iterations int
	FollowFork bool
	MultiThreaded bool
	Exec bool
	StraceOutPath string
	KcovOutPath string
	Name string
}

type StraceConfig struct {
	Name string
	StracePath string
	KcovPath string
}

type KcovEntry struct {
	Pid int
	Syscall int
	Ips []string
	StraceMeta *parser.OutputLine
}

type KcovEntries []KcovEntry

func (slice KcovEntries) Len() int {
	return len(slice)
}

func (slice KcovEntries) Less(i, j int) bool {
	return len(slice[i].Ips) < len(slice[j].Ips)
}

func (slice KcovEntries) Swap(i, j int) {
	slice[i], slice[j] = slice[j], slice[i]
}

func extractPidSyscall(s string) (pid int, syscall int, err error) {
	sp := strings.Split(s, "-")
	if len(sp) != 2 {
		return -1, -1, nil
	}
	if pid, err = strconv.Atoi(sp[0]); err != nil {
		return -1, -1, err
	}
	if syscall, err = strconv.Atoi(sp[1]); err != nil {
		return -1, -1, err
	}
	err = nil
	return
}

func write(client *storage.Client, bucket, objectName string, data []byte) error {
	ctx := context.Background()
	// [START upload_file]
	wc := client.Bucket(bucket).Object(objectName).NewWriter(ctx)

	if _, err := wc.Write(data); err != nil {
		return err
	}
	if err := wc.Close(); err != nil {
		return err
	}
	// [END upload_file]
	return nil
}

func create(client *storage.Client, projectId, bucketName string) error {
	ctx := context.Background()
	attrs := &storage.BucketAttrs{
		StorageClass: "MULTI_REGIONAL",
	}
	return client.Bucket(bucketName).Create(ctx, projectId, attrs)
}

func gatherCoverageStats(seenIps map[string]bool, entries KcovEntries) PerProgramStats {
	seenIpsProgram := make(map[string]bool)
	sort.Sort(entries)
	progStats := PerProgramStats{UniqueIps: 0, CallBreakdown: make([]PerCallCoverage, 0)}
	for _, entry := range entries {
		//perCallCoverage := PerCallCoverage{SysNR: entry.Syscall, UniqueIps: 0}
		for _, ip := range entry.Ips {
			if _, ok := seenIpsProgram[ip]; !ok {
				//We haven't seen this ip
				seenIpsProgram[ip] = true
		//		perCallCoverage.UniqueIps += 1
				progStats.UniqueIps += 1
				if _, ok_ := seenIps[ip]; !ok_ {
					seenIps[ip] = true
				}
			}
		}
		//progStats.CallBreakdown = append(progStats.CallBreakdown, perCallCoverage)
	}
	runtime.GC()
	return progStats
}

func mergeStraceKcov(client *storage.Client, seenIps map[string]bool, objectName, stracePath, kcovPath string) error {
	var err error
	var fdStrace *os.File
	var kcovData []byte
	var line *parser.OutputLine
	if fdStrace, err = os.Open(stracePath); err != nil {
		logrus.Fatalf("Unable to read strace: %s", err.Error())
	}
	sparser := parser.NewParser(fdStrace)
	straceLines := make([]*parser.OutputLine, 0)
	i := 0
	for {
		i++
		if line, err = sparser.Parse(); err != nil {
			if err == parser.ErrEOF {
				break;
			} else {
				logrus.Fatalf("Error reading file: %s at line: %d", err.Error(), i)
			}
		}
		straceLines = append(straceLines, line)
	}
	logrus.Printf("here")
	if kcovData, err = ioutil.ReadFile(kcovPath); err != nil {
		logrus.Fatalf("Unable to read kcov: %s", err.Error())
	}
	lines := strings.Split(string(kcovData), "\n")
	entries := make([]KcovEntry, 0)
	for _, line := range lines {
		var pid, syscall int
		var err error
		sysCovInfo := strings.Split(line, ":")
		if len(sysCovInfo) != 3 {
			logrus.Debugf("Coverage Len != 3: %d\n", len(sysCovInfo))
			continue
		} else {
			if sysCovInfo[1] == "" {
				logrus.Debugf("No coverage, skipping")
				continue
			}
			pid, syscall, err = extractPidSyscall(sysCovInfo[0])
			if err != nil {
				logrus.Debugf("error extracting pid, syscall: %s", err.Error())
			}
			if _, ok := unsupported[syscall]; ok {
				continue
			}
			ips := strings.Split(sysCovInfo[1], ",")

			entry := KcovEntry{
				Pid: pid,
				Syscall: syscall,
				Ips: ips,
			}
			entries = append(entries, entry)
		}
	}

	i = 0
	entryLen := len(entries)
	straceLen := len(straceLines)
	logrus.Printf("strace_len: %d", straceLen)
	consecutive_match := 0

	for j, line := range straceLines {
		if i >= entryLen {
			break
		}
		if _, ok := sys.CallMap[line.FuncName]; !ok {
			logrus.Printf("line: %s, %d", line.FuncName, j)
			continue
		}
		j := i
		for k, entry := range entries[j:] {
			var syscall int = sys.CallMap[line.FuncName].NR
			if entry.Syscall == syscall {
				consecutive_match += 1
				entry.StraceMeta = line
				entries[j+k] = entry
				i = j + k + 1
				break
			}
		}
	}


	perProgStats := gatherCoverageStats(seenIps, KcovEntries(entries))
	logrus.Printf("%v", perProgStats)


	dat, _ := json.Marshal(entries)

	err = write(client, "corpus-distilled", "merged/" + objectName, dat)
	if err != nil {
		logrus.Fatalf("%s", err.Error())
	}

	dat, _ = ioutil.ReadFile(stracePath)
	err = write(client, "corpus-distilled", "strace/" + objectName, dat)
	if err != nil {
		logrus.Fatalf("%s", err.Error())
	}

	dat, _ = json.Marshal(entries)
	err = write(client, "corpus-distilled", "kcov/" + objectName, dat)
	if err != nil {
		logrus.Fatalf("%s", err.Error())
	}

	return err
}

func buildStraceCmd(config WorkloadConfig) exec.Cmd {
	straceCmd := exec.Cmd{}
	straceCmd.Path = "/root/strace" //Add to config
	straceCmd.Args = append([]string{straceCmd.Path}, "-s")
	straceCmd.Args = append(straceCmd.Args, "65500")
	straceCmd.Args = append(straceCmd.Args, "-o")
	straceCmd.Args = append(straceCmd.Args, config.StraceOutPath)
	if config.FollowFork {
		straceCmd.Args = append(straceCmd.Args, "-ff")
	}
	straceCmd.Args = append(straceCmd.Args, config.ExecutablePath)
	return straceCmd
}

func buildKcovCmd(config WorkloadConfig) exec.Cmd {
	kcovCmd := exec.Cmd{}
	kcovCmd.Path = "/root/kcov" //Add to config
	kcovCmd.Args = append([]string{kcovCmd.Path}, "-o")
	kcovCmd.Args = append(kcovCmd.Args, config.KcovOutPath)
	if config.FollowFork {
		kcovCmd.Args = append(kcovCmd.Args, "-ff")
	}
	kcovCmd.Args = append(kcovCmd.Args, config.ExecutablePath)
	return kcovCmd
}

func main() {
	var err error
	var skipGeneration bool
	var configFile string
	flag.BoolVar(&skipGeneration, "skipGen", false, "skip the generation of coverage")
	flag.StringVar(&configFile, "config", "", "path to workload config file")
	flag.Parse()
	ctx := context.Background()

	client, err := storage.NewClient(ctx)
	if err != nil {
		logrus.Fatalf("%s", err.Error())
	}
	if err != nil {
		logrus.Fatalf("%s", err.Error())
	}

	if err != nil {
		logrus.Fatalf("Failed to initialize client: %s", err.Error())
	}
	args := os.Args
	if len(args) < 1 {
		os.Exit(1)
	}
	data, fileErr := ioutil.ReadFile(configFile)
	if fileErr != nil {
		logrus.Fatalf("Unable to read config, exiting")
	}
	configs := make([]WorkloadConfig, 0)
	if err := json.Unmarshal(data, &configs); err != nil {
		logrus.Fatalf("Unable to read config")
	}
	logrus.Printf("configs: %v", configs)

	if (skipGeneration == false) {
		for _, config := range configs {
			var stderr bytes.Buffer
			var stdout bytes.Buffer

			straceCmd := buildStraceCmd(config)
			straceCmd.Stdout = &stdout
			straceCmd.Stderr = &stderr
			if err = straceCmd.Run(); err != nil {
				logrus.Printf("%s", stderr.String())
				logrus.Printf("%s", stdout.String())
				logrus.Fatalf("%s", err.Error())
			}
			kcovCmd := buildKcovCmd(config)
			kcovCmd.Stdout = &stdout
			kcovCmd.Stderr = &stderr
			if err = kcovCmd.Run(); err != nil {
				logrus.Printf("%s", stderr.String())
				logrus.Printf("%s", stdout.String())
				logrus.Fatalf("%s", err.Error())
			}
		}
	}
	logrus.Infof("Finished Kcov")
	//Read strace output
	//Read kcov output
	seenIps := make(map[string]bool)
	for _, config := range configs {
		mergeStraceKcov(client, seenIps, config.Name, config.StraceOutPath, config.KcovOutPath)
		runtime.GC()
	}
	logrus.Printf("seen ips: %d", len(seenIps))
}
