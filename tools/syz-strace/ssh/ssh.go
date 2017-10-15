package syz_ssh

import (
	"bytes"
	"fmt"
	"io"
	"io/ioutil"
	"golang.org/x/crypto/ssh"
	"strings"
	"os"
	"github.com/Sirupsen/logrus"
	"github.com/pkg/sftp"
	"github.com/google/syzkaller/tools/syz-strace/domain"
)

type SSHCommand struct {
	Path string
	Args []string
	Env []string
	Stdin io.Reader
	Stdout io.Writer
	Stderr io.Writer
}

type SSHClient struct {
	Config *ssh.ClientConfig
	Host string
	DestDir string
	Port int
}

func NewClient(port int, destDir, sshKey, sshUser, host string) (client *SSHClient) {
	fmt.Printf("Ssh user: %s\n", sshUser)
	fmt.Printf("Ssh key: %s\n", sshKey)
	fmt.Printf("host key: %s\n", host)
	sshConfig := &ssh.ClientConfig{
		User: sshUser,
		Auth: []ssh.AuthMethod{
			PublicKeyFile(sshKey),
		},
		HostKeyCallback: ssh.InsecureIgnoreHostKey(),
	}
	client = &SSHClient{
		Config: sshConfig,
		Host:   host,
		Port:   port,
		DestDir: destDir,
	}
	return
}

func (cmd *SSHCommand) build() string {
	var command_buffer bytes.Buffer

	for i, arg := range cmd.Args {
		command_buffer.WriteString(arg)
		if i < len(cmd.Args) -1 {
			command_buffer.WriteString(" ")
		}
	}
	logrus.Infof("Command: %s\n", command_buffer.String())
	return command_buffer.String()
}

func (client *SSHClient) extractCommand(config domain.WorkloadConfig) (sshCommand *SSHCommand){
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
	return sshCommand
}

func (client *SSHClient) RunStrace(config domain.WorkloadConfig)  error {
	cmd := client.extractCommand(config)
	if err := client.runCommand(cmd); err != nil {
		logrus.Errorf("Failed to run command: %s", err.Error())
		return err
	}
	client.copyPath(config.StraceOutPath, client.DestDir + "/" + config.Name)
	client.deleteFile(config)
	return nil
}

func (client *SSHClient) runCommand(cmd *SSHCommand) error{
	var (
		session *ssh.Session
		err     error
	)
	if session, err = client.newSession(); err != nil {
		return err
	}
	defer session.Close()

	if err = client.prepareCommand(session, cmd); err != nil {
		return err
	}

	err = session.Run(cmd.build())
	return err

}

func (client *SSHClient) copyPath(srcPath, destPath string) {
	fdest, err := os.OpenFile(destPath, os.O_CREATE|os.O_APPEND|os.O_RDWR, 0600)
	if err != nil {
		logrus.Fatalf("failed to open dest path: %s", err.Error())
	}
	conn, err := client.newConnection()
	if err != nil {
		logrus.Fatalf("failed to open connection in CopyPath: %s", err.Error())
	}
	sftp, err := sftp.NewClient(conn)
	if err != nil {
		logrus.Fatalf("failed to initialize sftp: %s", err.Error())
	}
	f, err := sftp.Open(srcPath)
	if err != nil {
		logrus.Fatalf("failed to open remote file: %s with error: %s", srcPath, err.Error())
	}
	data, err := ioutil.ReadAll(f)
	if err != nil {
		logrus.Fatalf("failed to read remote file: %s with error: %s", srcPath, err.Error())
	}
	err = ioutil.WriteFile(fdest.Name(), data, 0600)
	if err != nil {
		logrus.Fatalf("failed to write to remote file: %s with error: %s", destPath, err.Error())
	}
	return
}

func (client *SSHClient) prepareCommand(session *ssh.Session, cmd *SSHCommand) error {
	for _, env := range cmd.Env {
		variable := strings.Split(env, "=")
		if len(variable) != 2 {
			continue
		}

		if err := session.Setenv(variable[0], variable[1]); err != nil {
			return err
		}
	}

	if cmd.Stdin != nil {
		stdin, err := session.StdinPipe()
		if err != nil {
			return fmt.Errorf("Unable to setup stdin for session: %v", err)
		}
		go io.Copy(stdin, cmd.Stdin)
	}

	if cmd.Stdout != nil {
		stdout, err := session.StdoutPipe()
		if err != nil {
			return fmt.Errorf("Unable to setup stdout for session: %v", err)
		}
		go io.Copy(cmd.Stdout, stdout)
	}

	if cmd.Stderr != nil {
		stderr, err := session.StderrPipe()
		if err != nil {
			return fmt.Errorf("Unable to setup stderr for session: %v", err)
		}
		go io.Copy(cmd.Stderr, stderr)
	}

	return nil
}

func (client *SSHClient) deleteFile(config domain.WorkloadConfig) {
	deleteCmd := new(SSHCommand)
	deleteCmd.Path = "/bin/rm"
	deleteCmd.Args = append([]string{deleteCmd.Path}, "-f")
	deleteCmd.Args = append(deleteCmd.Args, config.StraceOutPath)
	if err := client.runCommand(deleteCmd); err != nil {
		logrus.Fatalf("Failed to delete output file: %s", err.Error())
	}
}


func (client *SSHClient) newSession() (*ssh.Session, error) {
	connection, err := client.newConnection()
	if err != nil {
		logrus.Fatalf("Failed to initialize connection: %s", err.Error())
	}
	session, err := connection.NewSession()
	if err != nil {
		return nil, fmt.Errorf("Failed to create session: %s", err)
	}

	modes := ssh.TerminalModes{
		// ssh.ECHO:          0,     // disable echoing
		ssh.TTY_OP_ISPEED: 14400, // input speed = 14.4kbaud
		ssh.TTY_OP_OSPEED: 14400, // output speed = 14.4kbaud
	}

	if err := session.RequestPty("xterm", 80, 40, modes); err != nil {
		session.Close()
		return nil, fmt.Errorf("request for pseudo terminal failed: %s", err)
	}

	return session, nil
}

func (client *SSHClient) newConnection() (*ssh.Client, error) {
	connection, err := ssh.Dial("tcp", fmt.Sprintf("%s:%d", client.Host, client.Port), client.Config)
	if err != nil {
		return nil, fmt.Errorf(fmt.Sprintf("Failed to dial: %s", err.Error()))
	}
	return connection, err
}

func PublicKeyFile(file string) ssh.AuthMethod {
	buffer, err := ioutil.ReadFile(file)
	if err != nil {
		return nil
	}

	key, err := ssh.ParsePrivateKey(buffer)
	key.PublicKey()
	if err != nil {
		fmt.Printf("Failed to print private key: %s\n", err.Error())
		return nil
	}
	return ssh.PublicKeys(key)
}
