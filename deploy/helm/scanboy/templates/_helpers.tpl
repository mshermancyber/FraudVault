{{- define "scanboy.name" -}}
{{- default .Chart.Name .Values.nameOverride | trunc 63 | trimSuffix "-" }}
{{- end }}

{{- define "scanboy.fullname" -}}
{{- if .Values.fullnameOverride }}
{{- .Values.fullnameOverride | trunc 63 | trimSuffix "-" }}
{{- else }}
{{- $name := default .Chart.Name .Values.nameOverride }}
{{- if contains $name .Release.Name }}
{{- .Release.Name | trunc 63 | trimSuffix "-" }}
{{- else }}
{{- printf "%s-%s" .Release.Name $name | trunc 63 | trimSuffix "-" }}
{{- end }}
{{- end }}
{{- end }}

{{- define "scanboy.chart" -}}
{{- printf "%s-%s" .Chart.Name .Chart.Version | replace "+" "_" | trunc 63 | trimSuffix "-" }}
{{- end }}

{{- define "scanboy.labels" -}}
helm.sh/chart: {{ include "scanboy.chart" . }}
{{ include "scanboy.selectorLabels" . }}
app.kubernetes.io/version: {{ .Chart.AppVersion | quote }}
app.kubernetes.io/managed-by: {{ .Release.Service }}
{{- end }}

{{- define "scanboy.selectorLabels" -}}
app.kubernetes.io/name: {{ include "scanboy.name" . }}
app.kubernetes.io/instance: {{ .Release.Name }}
{{- end }}

{{- define "scanboy.serviceLabels" -}}
{{ include "scanboy.labels" . }}
app.kubernetes.io/component: {{ .component }}
{{- end }}

{{- define "scanboy.serviceSelectorLabels" -}}
{{ include "scanboy.selectorLabels" . }}
app.kubernetes.io/component: {{ .component }}
{{- end }}
