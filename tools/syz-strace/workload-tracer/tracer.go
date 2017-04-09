package workload_tracer

import (
	"io/ioutil"
	"github.com/Sirupsen/logrus"
	"encoding/json"
	"cloud.google.com/go/storage"
	"golang.org/x/net/context"
	. "github.com/google/syzkaller/tools/syz-strace/ssh"
	"github.com/google/syzkaller/tools/syz-strace/config"

)

type WorkloadConfig struct {
	ExecutablePath string
	Iterations int
	FollowFork bool
	Args []string
	StraceOutPath string
	KcovOutPath string
	Name string
}

func write(client *storage.Client, bucket, objectName string, data []byte) error {
	ctx := context.Background()
	// [START upload_file]
	wc := client.Bucket(bucket).Object(objectName).NewWriter(ctx)

	if _, err := wc.Write(data); err != nil {
		return err
	}
	if err := wc.Close(); err != nil {
		return err
	}
	// [END upload_file]
	return nil
}

func create(client *storage.Client, projectId, bucketName string) error {
	ctx := context.Background()
	attrs := &storage.BucketAttrs{
		StorageClass: "MULTI_REGIONAL",
	}
	return client.Bucket(bucketName).Create(ctx, projectId, attrs)
}

func GenerateCorpus(genConfig config.CorpusGenConfig) (err error) {
	//ctx := context.Background()
	//client, err := storage.NewClient(ctx)
	client := NewClient(genConfig)
	if err != nil {
		logrus.Fatalf("Unable to generate client config: %s", err.Error())
	}
	wcs := readWorkload(genConfig.ConfigPath)
	for _, wc := range wcs {
		RunStrace(wc, client)
		client.CopyPath(wc.StraceOutPath, "/home/w4118/src/github.com/google/syzkaller/strace-output/ls_test")
		DeleteOutFile(wc, client)
	}
	return
}

func RunStrace(wc WorkloadConfig, client *SSHClient) error{
	var err error
	straceCmd := buildStraceCmd(wc)
	logrus.Infof("cmd: %v\n", straceCmd);
	if err = client.RunCommand(straceCmd); err != nil {
		logrus.Fatalf("Failed to run prog: %s, with error: %s", wc.ExecutablePath, err.Error())
	}
	return err
}

func DeleteOutFile(config WorkloadConfig, client *SSHClient) {
	deleteCmd := new(SSHCommand)
	deleteCmd.Path = "/bin/rm"
	deleteCmd.Args = append([]string{deleteCmd.Path}, "-f")
	deleteCmd.Args = append(deleteCmd.Args, config.StraceOutPath)
	if err := client.RunCommand(deleteCmd); err != nil {
		logrus.Fatalf("Failed to delete output file: %s", err.Error())
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

func buildStraceCmd(config WorkloadConfig) (sshCommand *SSHCommand) {
	sshCommand = new(SSHCommand)
	sshCommand.Path = "/root/strace"
	sshCommand.Args = make([]string, 0)
	sshCommand.Args = append([]string{"/root/strace"}, "-s")
	sshCommand.Args = append(sshCommand.Args, "65500")
	sshCommand.Args = append(sshCommand.Args, "-o")
	sshCommand.Args = append(sshCommand.Args, config.StraceOutPath)
	sshCommand.Args = append(sshCommand.Args, "-k")
	if config.FollowFork {
		sshCommand.Args = append(sshCommand.Args, "-f")
	}
	sshCommand.Args = append(sshCommand.Args, config.ExecutablePath)
	sshCommand.Args = append(sshCommand.Args, config.Args...)
	return
}

