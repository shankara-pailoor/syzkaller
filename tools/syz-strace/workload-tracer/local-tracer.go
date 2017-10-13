package workload_tracer

import (
	"github.com/Sirupsen/logrus"
	. "github.com/google/syzkaller/tools/syz-strace/domain"
)

type DefaultTracer struct {
	executor Executor
	workloads []WorkloadConfig
}


func (dt *DefaultTracer) GenerateCorpus() (err error) {
	//ctx := context.Background()
	//client, err := storage.NewClient(ctx)
	if err != nil {
		logrus.Fatalf("Unable to generate client config: %s", err.Error())
	}
	for _, wc := range dt.workloads {
		if err = dt.executor.RunStrace(wc); err != nil {
			return err
		}
	}
	return
}
