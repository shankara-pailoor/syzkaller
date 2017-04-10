package domain

type Executor interface {
	RunCommand(wc WorkloadConfig) error
	CopyPath(string, string)
	DeleteFile(wc WorkloadConfig)
}
