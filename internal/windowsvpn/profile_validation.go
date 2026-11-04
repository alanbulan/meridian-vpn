package windowsvpn

import (
	"bytes"
	"unicode/utf8"
)

// ValidateBorrowedSelection is lexical validation only. It performs no file or
// native access, proves no Windows profile identity, and grants no permission.
func ValidateBorrowedSelection(entry PhonebookEntry, gateway, username, domain string) error {
	if !validSelection(entry) || !validText(username, 256) || len(username) > 1024 || domain == "*" || len(domain) > 60 || (domain != "" && !validText(domain, 15)) {
		return ErrVerification
	}
	if _, ok := canonicalGateway(gateway); !ok {
		return ErrVerification
	}
	return nil
}
func ValidateBorrowedPassword(password []byte) error {
	if len(password) == 0 || len(password) > 1024 || !utf8.Valid(password) || bytes.ContainsAny(password, "\x00\r\n") || secretUnits(password) > 256 {
		return ErrOperation
	}
	return nil
}
