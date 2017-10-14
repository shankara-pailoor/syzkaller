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
			executor = syz_ssh.NewClient(config.SshPort, config.SshUser, config.SshKey, ip)
		default:
			panic("Only ssh executor supported\n")
		}
		tracer.executor = append(tracer.executor, executor)
	}

	return
}


func (tracer *GCETracer) GenerateCorpus() (err error) {
	fmt.Printf("some dummy value\n")
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
		"-i ", tracer.sshkey,
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