package workload_tracer

import (

	"github.com/google/syzkaller/tools/syz-strace/config"
	"io/ioutil"
	"github.com/Sirupsen/logrus"
	"encoding/json"
	. "github.com/google/syzkaller/tools/syz-strace/domain"
	"github.com/google/syzkaller/tools/syz-strace/ssh"
)


type Tracer interface {
	GenerateCorpus() (err error)
}

func NewTracer(config config.CorpusGenConfig) (tracer Tracer) {
	var executor Executor
	switch config.Executor {
	case "ssh":
		executor = syz_ssh.NewClient(config.SSHConfig)
	default:
		panic("Only ssh executor supported\n")
	}

	switch config.Tracer {
	default:
		workloads := readWorkload(config.ConfigPath)
		tracer = &DefaultTracer{executor: executor, workloads: workloads}
	}
	return
}

func readWorkload(location string) (wcs []WorkloadConfig) {
	data, fileErr := ioutil.ReadFile(location)
	if fileErr != nil {
		logrus.Fatalf("Unable to read config, exiting")
	}
	if err := json.Unmarshal(data, &wcs); err != nil {
		logrus.Fatalf("Unable to read config")
	}
	return
}
