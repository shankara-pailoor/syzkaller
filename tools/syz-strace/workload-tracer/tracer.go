package workload_tracer

import (

	"github.com/google/syzkaller/tools/syz-strace/config"
	"io/ioutil"
	"github.com/Sirupsen/logrus"
	"encoding/json"
	. "github.com/google/syzkaller/tools/syz-strace/domain"
)


type Tracer interface {
	GenerateCorpus() (err error)
}

func NewTracer(config config.CorpusGenConfig) (tracer Tracer) {


	switch config.Tracer {
	case "gce":
		tracer = NewGCETracer(config)
	default:
		tracer = NewDefaultTracer(config)
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
