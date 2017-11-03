package workload_tracer

import (

	"github.com/google/syzkaller/tools/syz-strace/config"
	"io/ioutil"
	"github.com/Sirupsen/logrus"
	"encoding/json"
	. "github.com/google/syzkaller/tools/syz-strace/domain"
	"os"
	"strings"
	"path/filepath"
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
	reader := func (file string) {
		tmpWcs := make([]WorkloadConfig, 0)
		if strings.Contains(file, ".json") {
			data, fileErr := ioutil.ReadFile(file)
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
	switch mode := finfo.Mode(); {
	case mode.IsDir():
		var finfos []os.FileInfo
		if finfos, err = ioutil.ReadDir(location); err != nil {
			panic(err.Error())
		}
		for _, file := range finfos {
			reader(filepath.Join(location, file.Name()))
		}
	default:
		reader(location)
	}

	return
}
