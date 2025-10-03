{{- define "ok" -}}
OK
{{end}}
{{- define "found" -}}
{{with $r := .}}{{range $id, $v := .PackageVulnerabilities}}{{range $d := $v -}}
Found	{{with index $r.Packages $id}}{{.Name}}	{{.Version}}{{end}}
	{{- with index $r.Vulnerabilities $d}}	{{.Name}}
	{{- with .FixedInVersion}}	(fixed: {{.}}){{end}}{{end}}
{{end}}{{end}}{{end}}{{end}}
{{- /* The following is the actual bit of the template that runs per item. */ -}}
{{- if ne (len .PackageVulnerabilities) 0}}{{template "found" .}}
{{- else}}{{template "ok" .}}
{{- end}}
