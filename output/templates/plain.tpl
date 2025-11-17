{{- define "ok" -}}
No CVEs found.
{{end}}
{{- define "found" -}}
Name	Version	Identifier	Severity / Normalized Severity	Fixed in Version
----	-------	----------	------------------------------	----------------
{{with $r := .}}{{range $id, $v := .PackageVulnerabilities}}{{range $d := $v -}}
{{with index $r.Packages $id}}{{.Name}}	{{.Version}}{{end}}
	{{- with index $r.Vulnerabilities $d}}	{{.Name}}	{{.Severity}} / {{.NormalizedSeverity}}
	{{- with .FixedInVersion}}	(fixed: {{.}}){{end}}{{end}}
{{end}}{{end}}{{end}}{{end}}
{{- /* The following is the actual bit of the template that runs per item. */ -}}
{{- if ne (len .PackageVulnerabilities) 0}}{{template "found" .}}
{{- else}}{{template "ok" .}}
{{- end}}
