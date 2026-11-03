package main

import (
	"fmt"
	"io"
	"mygo-vpn/internal/core"
)

func (a application) previewINI(args []string, out, errOut io.Writer) int {
	f := newFlags("profiles preview-ini")
	input := f.String("file", "", "Input INI file")
	jsonOutput := f.Bool("json", false, "JSON output")
	if !parseFlags(f, args) || *input == "" {
		return usageError(errOut)
	}
	r, err := core.PreviewINIFile(*input)
	if err != nil {
		return failure(errOut, "INI file cannot be safely read or parsed; no configuration was changed.")
	}
	if *jsonOutput {
		return outputResult(writeJSON(out, r), errOut)
	}
	_, err = fmt.Fprintf(out, "Read-only INI inspection: %d sections, %d entries, %d recognized credential fields, %d unclassified fields.\nAll names and values are hidden. No configuration was imported or changed.\nVendor schema and protocol compatibility are NOT verified.\n", r.Sections, r.Entries, r.CredentialFields, r.UnknownFields)
	return outputResult(err, errOut)
}
