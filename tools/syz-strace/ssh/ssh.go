package syz_ssh

import (
	"bytes"
	"fmt"
	"io"
	"io/ioutil"
	"golang.org/x/crypto/ssh"
	"strings"
	"github.com/Sirupsen/logrus"
	"github.com/google/syzkaller/tools/syz-strace/config"
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
	Port int
}

func NewClient(config config.CorpusGenConfig) (client *SSHClient) {
	sshConfig := &ssh.ClientConfig{
		User: "jsmith",
		Auth: []ssh.AuthMethod{
			PublicKeyFile(config.KeyFile),
		},
	}
	client = &SSHClient{
		Config: sshConfig,
		Host:   config.Ip,
		Port:   config.Port,
	}
	return
}

func (cmd *SSHCommand) build() string {
	var command_buffer bytes.Buffer

	command_buffer.WriteString(cmd.Path)
	command_buffer.WriteString(" ")
	for i, arg := range cmd.Args {
		command_buffer.WriteString(arg)
		if i < len(cmd.Args) -1 {
			command_buffer.WriteString(" ")
		}
	}
	logrus.Infof("Command: %s\n", command_buffer.String())
	return command_buffer.String()
}

func (client *SSHClient) RunCommand(cmd *SSHCommand) error{
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

func (client *SSHClient) newSession() (*ssh.Session, error) {
	connection, err := ssh.Dial("tcp", fmt.Sprintf("%s:%d", client.Host, client.Port), client.Config)
	if err != nil {
		return nil, fmt.Errorf("Failed to dial: %s", err)
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

func PublicKeyFile(file string) ssh.AuthMethod {
	buffer, err := ioutil.ReadFile(file)
	if err != nil {
		return nil
	}

	key, err := ssh.ParsePrivateKey(buffer)
	if err != nil {
		return nil
	}
	return ssh.PublicKeys(key)
}