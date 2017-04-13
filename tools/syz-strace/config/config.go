package config

import (
	"io/ioutil"
	"github.com/Sirupsen/logrus"
	"encoding/json"
)

type SyzStraceConfig struct {
	CorpusGenConf CorpusGenConfig `json:"corpus_gen_conf"`
	ParserConf ParserConfig `json:"parser_conf"`
	DistillConf DistillConfig `json:"distill_conf"`
}

type CorpusGenConfig struct {
	ConfigPath string `json:"workload_config"`
	Type string
	SSHConfig
	DestinationDir string `json:"dest_dir"`
}

type DistillConfig struct {
	Type string
	Stats string `json:"stats"`
}

type ParserConfig struct {
	Type string
	LocalConfig
}

type SSHConfig struct {
	Ip string
	Port int
	KeyFile string `json:"ssh_key"`
}

type LocalConfig struct {
	InputDirectory string
	Files []string
	Filter []string
	OutputDirectory string
}

type GceConfig struct {

}

func NewConfig(location string) (config *SyzStraceConfig) {
	dat, fileErr := ioutil.ReadFile(location)
	if fileErr != nil {
		logrus.Fatalf("Unable to read config, exiting")
	}
	if err := json.Unmarshal(dat, &config); err != nil {
		logrus.Fatalf("Unable to read config: %s", err.Error())
	}
	return
}
