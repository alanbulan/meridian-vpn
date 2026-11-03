//go:build !linux

package autostart

func checkExecutable(string) error                   { return ErrUnsupported }
func (m *Manager) readRegistration() (string, error) { return "", ErrUnsupported }
func (m *Manager) enable([]byte) error               { return ErrUnsupported }
func (m *Manager) disable() error                    { return ErrUnsupported }
