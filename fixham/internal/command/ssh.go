package command

import (
	"bytes"
	"os"
	"strings"
	"time"

	"golang.org/x/crypto/ssh"
)

type SSHConfig struct {
	Host    string
	User    string
	KeyPath string
	Port    string
}

func NewSSHConfig(host, user, keyPath, port string) *SSHConfig {
	return &SSHConfig{
		Host:    host,
		User:    user,
		KeyPath: keyPath,
		Port:    port,
	}
}

// Args returns the ssh command string
func (s *SSHConfig) Args() string {
	str := []string{"-i", s.KeyPath, "-p", s.Port, "-q", "-o StrictHostKeyChecking=no", "-o UserKnownHostsFile=/dev/null"}
	return strings.Join(str, " ")
}

func (s *SSHConfig) HostString() string {
	return s.User + "@" + s.Host

}

func connect(sshConfig *SSHConfig) (*ssh.Session, error) {
	key, err := os.ReadFile(sshConfig.KeyPath)
	if err != nil {
		return nil, err
	}
	signer, err := ssh.ParsePrivateKey(key)
	if err != nil {
		return nil, err
	}
	config := &ssh.ClientConfig{
		User: sshConfig.User,
		Auth: []ssh.AuthMethod{
			ssh.PublicKeys(signer),
		},
		HostKeyCallback: ssh.InsecureIgnoreHostKey(),
		Timeout:         10 * time.Second,
	}
	client, err := ssh.Dial("tcp", sshConfig.Host+":"+sshConfig.Port, config)
	if err != nil {
		return nil, err
	}
	session, err := client.NewSession()
	if err != nil {
		return nil, err
	}
	return session, nil
}

func RunSSHCommand(sshConfig *SSHConfig, command string) (string, error) {
	session, err := connect(sshConfig)
	if err != nil {
		return "", err
	}
	defer session.Close()
	var stdoutBuf bytes.Buffer
	session.Stdout = &stdoutBuf
	if err := session.Run(command); err != nil {
		return "", err
	}
	return stdoutBuf.String(), nil
}
