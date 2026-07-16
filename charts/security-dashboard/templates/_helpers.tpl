{{- define "security-dashboard.labels" -}}
app.kubernetes.io/name: security-dashboard-api
app.kubernetes.io/instance: {{ .Release.Name }}
app.kubernetes.io/version: {{ .Chart.AppVersion | quote }}
app.kubernetes.io/managed-by: {{ .Release.Service }}
helm.sh/chart: {{ printf "%s-%s" .Chart.Name .Chart.Version }}
{{- end }}

{{- define "security-dashboard.selectorLabels" -}}
app.kubernetes.io/name: security-dashboard-api
{{- end }}

{{- define "security-dashboard.image" -}}
{{ .Values.image.repository }}:{{ .Values.image.tag | default .Chart.AppVersion }}
{{- end }}
