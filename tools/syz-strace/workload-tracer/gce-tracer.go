package workload_tracer

import (
	. "github.com/google/syzkaller/tools/syz-strace/domain"
	. "github.com/google/syzkaller/pkg/gce"
	"github.com/google/syzkaller/tools/syz-strace/config"
	"fmt"
	"github.com/google/syzkaller/pkg/osutil"
	"time"
	"github.com/google/syzkaller/tools/syz-strace/ssh"
)

type GCETracer struct {
	GCE *Context
	numinstances int
	machinetype  string
	imagename    string
	sshkey       string
	sshuser      string
	executor     []Executor
	workloads    []WorkloadConfig
}

func NewGCETracer(config config.CorpusGenConfig) (tracer *GCETracer){
	var err error
	var GCE *Context
	GCE, err =  NewContext()
	if err != nil {
		panic(fmt.Sprintf("Error creating GCE context: %s", err.Error()))
		return
	}

	tracer = &GCETracer{
		GCE: GCE,
		numinstances: config.NumInstances,
		machinetype: config.MachineType,
		imagename: config.ImageName,
		executor: make([]Executor, 0),
		sshkey: config.SshKey,
		sshuser: config.SshUser,

	}

	workloads := readWorkload(config.ConfigPath)
	tracer.workloads = workloads
	for i := 0; i < tracer.numinstances; i++ {
		var ip string
		var executor Executor

		fmt.Printf("Creating instance: %d\n", i)
		if ip, err = tracer.createInstance(fmt.Sprintf("tracer-%d", i)); err != nil {
			panic(fmt.Sprintf("Error creating GCE instance: %s", err.Error()))
		}
		switch config.Executor {
		case "ssh":
			executor = syz_ssh.NewClient(config.SshPort,
							config.DestinationDir,
							config.SshKey,
							config.SshUser, ip)
		default:
			panic("Only ssh executor supported\n")
		}
		tracer.executor = append(tracer.executor, executor)
	}

	return
}

func runExecutor(executor Executor, in chan WorkloadConfig, out chan bool) {
	for wc := range in {
		fmt.Printf("received workload: %s\n", wc.Name)
		if err := executor.RunStrace(wc); err != nil {
			fmt.Printf("Error: %s\n", err.Error())
		}
		out <- true
	}

}

func (tracer *GCETracer) GenerateCorpus() (err error) {
	recv_chan := make(chan bool)
	wc_chan := make(chan WorkloadConfig, len(tracer.workloads))
	for _, wc := range tracer.workloads {
		wc_chan <- wc
	}
	close(wc_chan)
	for _, exec := range tracer.executor {
		go runExecutor(exec, wc_chan, recv_chan)
	}
	seen := 0
	for b := range recv_chan {
		fmt.Printf("Bool: %b\n", b)
		seen += 1
		if (seen  == len(tracer.workloads)) {
			close(recv_chan)
			close(wc_chan)
		}
	}
	return nil

}

func (tracer *GCETracer) createInstance(name string) (string, error) {
	ok := false
	defer func() {
		if !ok {
			tracer.GCE.DeleteInstance(name, true)
		}
	}()
	ip, err := tracer.GCE.CreateInstance(name, tracer.machinetype, tracer.imagename, "")
	if err != nil {
		return "", nil
	}
	err = tracer.waitForBoot(ip)
	if err != nil {
		return "", nil
	}
	ok = true
	return ip, nil
}

func (tracer *GCETracer) deleteInstance(name string) (string, error) {
	ip, err := tracer.GCE.CreateInstance(name, tracer.machinetype, tracer.imagename, "")
	if err != nil {
		return "", nil
	}
	err = tracer.waitForBoot(ip)
	if err != nil {
		return "", nil
	}
	return ip, nil
}

func (tracer *GCETracer) waitForBoot(ip string) error {
	args := []string {
		"-p", "22",
		"-i", tracer.sshkey,
		"-F", "/dev/null",
		"-o", "UserKnownHostsFile=/dev/null",
		"-o", "BatchMode=yes",
		"-o", "IdentitiesOnly=yes",
		"-o", "StrictHostKeyChecking=no",
		"-o", "ConnectTimeout=10",
		tracer.sshuser+"@"+ip,
		"pwd",
	}
	for i := 0; i < 100; i++ {
		if _, err := osutil.RunCmd(time.Minute, "", "ssh", args...); err == nil {
			return nil
		}
		time.Sleep(5*time.Second)
	}
	return fmt.Errorf("Could not ssh to instance")
}