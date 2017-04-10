package config

import (
	"io/ioutil"
	"github.com/Sirupsen/logrus"
	"encoding/json"
)

type DistillConfig struct {
	CorpusGenConf CorpusGenConfig `json:"corpus_gen_conf"`
	InpIOConf InputIOConfig `json:"io"`
	DistillEnabled bool `json:"distill_enabled"`
}

type CorpusGenConfig struct {
	ConfigPath string `json:"workload_config"`
	Type string
	SSHConfig
	DestinationDir string `json:"dest_dir"`
}

type SSHConfig struct {
	Ip string
	Port int
	KeyFile string `json:"ssh_key"`
}

type InputIOConfig struct {
	InpType string `json:"type"`
	LocalConfig
	GceConf GceConfig
}

type LocalConfig struct {
	InputDirectory string
	Files []string
	Filter []string
	OutputDirectory string
}

type GceConfig struct {

}

func NewConfig(location string) (config *DistillConfig) {
	dat, fileErr := ioutil.ReadFile(location)
	if fileErr != nil {
		logrus.Fatalf("Unable to read config, exiting")
	}
	if err := json.Unmarshal(dat, &config); err != nil {
		logrus.Fatalf("Unable to read config: %s", err.Error())
	}
	return
}
