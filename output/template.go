package output

import (
	"embed"
	"fmt"
	"html"
	"io"
	"path"
	"strings"
	"text/template"

	"github.com/quay/claircore"
)

//go:embed templates/*
var templates embed.FS

type TemplateWriter struct {
	Output   io.Writer
	Template *template.Template
}

func (tw TemplateWriter) Write(vr *claircore.VulnerabilityReport) error {
	err := tw.Template.Execute(tw.Output, vr)
	if err != nil {
		return fmt.Errorf("failed to write with template: %w", err)
	}
	return nil
}

func NewTemplateWriter(output io.Writer, outputTemplate string) (*TemplateWriter, error) {
	templateFuncMap := template.FuncMap{}
	templateFuncMap["escapeString"] = func(input string) string {
		return strings.ReplaceAll(html.EscapeString(input), "\\", "\\\\")
	}
	templateFuncMap["inc"] = func(i int) int {
		return i + 1
	}
	templateFuncMap["base"] = path.Base

	tmpl, err := template.New("output template").Funcs(templateFuncMap).Parse(outputTemplate)
	if err != nil {
		return nil, fmt.Errorf("error parsing template: %w", err)
	}
	return &TemplateWriter{Output: output, Template: tmpl}, nil
}
