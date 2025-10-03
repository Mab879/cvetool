package output

import (
	"io"
)

func NewPlainWriter(buf io.Writer) (*TemplateWriter, error) {
	tfb, err := templates.ReadFile("templates/plain.tpl")
	if err != nil {
		return nil, err
	}
	tw, err := NewTemplateWriter(buf, string(tfb))
	if err != nil {
		return nil, err
	}
	return tw, nil
}
