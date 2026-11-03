package core

import (
	"context"
	"errors"
	"fmt"
	"os"
	"runtime"
	"strings"
)

type fileCommandRunner interface {
	RunWithFiles(context.Context, string, []string, []byte, []*os.File) ([]byte, error)
}

// authenticateOpenConnect uses fixed inherited FDs, never secret argv/env or
// filesystem config files. Certificates are held open through authentication so
// replacing their pathname cannot substitute a different key after validation.
func authenticateOpenConnect(ctx context.Context, runner commandRunner, executable string, p Profile, c Credentials) ([]byte, error) {
	if err := validateCredentials(p, c); err != nil {
		return nil, err
	}
	args, err := OpenConnectArgs(p)
	if err != nil {
		return nil, err
	}
	args = append([]string{"--authenticate"}, args...)
	input := append(append([]byte{}, c.Password...), '\n')
	defer clear(input)
	if p.ClientCertificate == "" && p.CAFile == "" {
		return runner.Run(ctx, executable, args, input)
	}
	if runtime.GOOS != "linux" {
		return nil, errors.New("client certificate authentication requires the Linux backend")
	}
	withFiles, ok := runner.(fileCommandRunner)
	if !ok {
		return nil, errors.New("backend cannot securely pass client certificate credentials")
	}
	certFiles, err := openClientCertificate(p)
	if err != nil {
		return nil, err
	}
	certCount := len(certFiles)
	caFile, err := openValidatedCAFile(p.CAFile)
	if err != nil {
		for _, f := range certFiles {
			f.Close()
		}
		return nil, err
	}
	if caFile != nil {
		caRef := fmt.Sprintf("--cafile=/proc/self/fd/%d", 4+len(certFiles))
		certFiles = append(certFiles, caFile)
		for i, arg := range args {
			if strings.HasPrefix(arg, "--cafile=") {
				args[i] = caRef
			}
		}
	}
	defer func() {
		for _, f := range certFiles {
			f.Close()
		}
	}()
	configReader, configWriter, err := os.Pipe()
	if err != nil {
		return nil, errors.New("cannot create private authentication channel")
	}
	defer configReader.Close()
	// The complete generated config fits within Linux PIPE_BUF (4096) only when
	// shorter than that bound. Write asynchronously so even longer accepted values
	// never block cancellation before starting the child.
	config := []byte("# client identity\n")
	if len(c.KeyPassword) > 0 {
		config = append([]byte("key-password="), c.KeyPassword...)
		config = append(config, '\n')
	}
	if p.CertificateFormat == "pkcs11" {
		config = append(config, []byte("certificate="+p.ClientCertificate+"\n")...)
		if p.ClientKey != "" {
			config = append(config, []byte("sslkey="+p.ClientKey+"\n")...)
		}
	}
	writeDone := make(chan struct{})
	go func() {
		defer close(writeDone)
		defer configWriter.Close()
		defer clear(config)
		_, _ = configWriter.Write(config)
	}()
	defer func() { configReader.Close(); configWriter.Close(); <-writeDone }()
	files := append([]*os.File{configReader}, certFiles...)
	identityArgs := []string{"--config=/proc/self/fd/3"}
	if p.CertificateFormat == "pkcs11" {
		// Selectors are validated non-secret references and travel in the private
		// config pipe, keeping token serials and labels out of process argv.
	} else if p.ClientCertificate != "" {
		identityArgs = append(identityArgs, "--certificate=/proc/self/fd/4")
		if certCount == 2 {
			identityArgs = append(identityArgs, "--sslkey=/proc/self/fd/5")
		}
	}
	args = append(identityArgs, args...)
	return withFiles.RunWithFiles(ctx, executable, args, input, files)
}
