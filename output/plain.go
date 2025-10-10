package output

import (
	"io"
	"text/tabwriter"
)

func NewPlainWriter(buf io.Writer) (*TemplateWriter, error) {
	tfb, err := templates.ReadFile("templates/plain.tpl")
	if err != nil {
		return nil, err
	}
	w := tabwriter.NewWriter(buf, 0, 0, 1, ' ', 0)
	tw, err := NewTemplateWriter(w, string(tfb))
	if err != nil {
		return nil, err
	}
	return tw, nil
}
