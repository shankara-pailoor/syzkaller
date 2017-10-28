package workload_tracer

import (
	. "github.com/google/syzkaller/tools/syz-strace/domain"
	"github.com/google/syzkaller/tools/syz-strace/ssh"
	"github.com/google/syzkaller/tools/syz-strace/config"
	"fmt"
)

type DefaultTracer struct {
	executor Executor
	workloads []WorkloadConfig
}

func NewDefaultTracer(config config.CorpusGenConfig) (tracer Tracer) {
	var executor Executor
	switch config.Executor {
	case "ssh":
		executor = syz_ssh.NewClient(config.SshPort,
			config.DestinationDir,
			config.SshKey,
			config.SshUser,
			"127.0.0.1")
	default:
		panic("Only ssh executor supported\n")
	}
	workloads := readWorkload(config.ConfigPath)
	tracer = &DefaultTracer{executor: executor, workloads: workloads}
	return
}


func (dt *DefaultTracer) GenerateCorpus() (err error) {
	//ctx := context.Background()
	//client, err := storage.NewClient(ctx)
	for _, wc := range dt.workloads {
		if err = dt.executor.RunStrace(wc); err != nil {
			fmt.Printf("Error generating strace: %s\n", err.Error())
			continue
		}
	}
	return
}
