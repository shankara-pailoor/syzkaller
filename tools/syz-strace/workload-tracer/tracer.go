package workload_tracer

import (
	"io/ioutil"
	"github.com/Sirupsen/logrus"
	"encoding/json"
	"cloud.google.com/go/storage"
	"golang.org/x/net/context"
	"github.com/google/syzkaller/tools/syz-strace/config"
	. "github.com/google/syzkaller/tools/syz-strace/domain"
)


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

func GenerateCorpus(genConfig config.CorpusGenConfig, executor Executor) (err error) {
	//ctx := context.Background()
	//client, err := storage.NewClient(ctx)
	if err != nil {
		logrus.Fatalf("Unable to generate client config: %s", err.Error())
	}
	wcs := readWorkload(genConfig.ConfigPath)
	for _, wc := range wcs {
		RunStrace(wc, executor, genConfig.DestinationDir)
	}
	return
}

func RunStrace(wc WorkloadConfig, client Executor, destDir string) error{
	var err error
	if err = client.RunCommand(wc); err != nil {
		logrus.Errorf("Failed to run prog: %s, with error: %s", wc.ExecutablePath, err.Error())
	}
	client.CopyPath(wc.StraceOutPath, destDir + "/" + wc.Name)
	client.DeleteFile(wc)
	return err
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
