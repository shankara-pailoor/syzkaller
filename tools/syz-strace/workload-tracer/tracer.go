package workload_tracer

import (

	"github.com/google/syzkaller/tools/syz-strace/config"
	"io/ioutil"
	"github.com/Sirupsen/logrus"
	"encoding/json"
	. "github.com/google/syzkaller/tools/syz-strace/domain"
	"os"
	"strings"
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
	reader := func (file os.FileInfo) {
		tmpWcs := make([]WorkloadConfig, 0)
		if strings.Contains(file.Name(), ".json") {
			data, fileErr := ioutil.ReadFile(location)
			if fileErr != nil {
				logrus.Fatalf("Unable to read config, exiting")
			}
			if err := json.Unmarshal(data, &tmpWcs); err != nil {
				logrus.Fatalf("Unable to read config")
			}
			wcs = append(wcs, tmpWcs...)
		}
	}
	finfo, err := os.Stat(location)
	if err != nil {
		panic(err.Error())
	}
	switch finfo.Mode() {
	case os.ModeDir:
		var finfos []os.FileInfo
		if finfos, err = ioutil.ReadDir(location); err != nil {
			panic(err.Error())
		}
		for _, file := range finfos {
			reader(file)
		}
	default:
		reader(finfo)
	}

	return
}
