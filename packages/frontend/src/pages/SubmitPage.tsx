import { useState, useCallback, FormEvent } from 'react';
import { useNavigate } from 'react-router-dom';
import { Upload, File, Link, Mail, Box, X, AlertCircle, Settings } from 'lucide-react';
import { api } from '@/lib/api';
import { clsx } from 'clsx';

type SubmissionType = 'file' | 'url' | 'email' | 'container' | 'container_url';
type NetworkMode = 'isolated' | 'simulated' | 'controlled';

const submissionTypes: Array<{
  type: SubmissionType;
  icon: typeof File;
  label: string;
  description: string;
}> = [
  {
    type: 'file',
    icon: Upload,
    label: 'Upload Suspicious File',
    description: 'Malware detonation — EXE, DLL, PDF, Office docs, scripts, archives',
  },
  {
    type: 'url',
    icon: Link,
    label: 'Link to Suspicious File',
    description: 'Download and detonate a suspicious file from a URL',
  },
  {
    type: 'email',
    icon: Mail,
    label: 'Suspicious Email',
    description: 'Malware analysis — EML or MSG with attachment extraction',
  },
  {
    type: 'container',
    icon: Box,
    label: 'Upload Container Image',
    description: 'Container scan — SBOM, CVE lookup, secrets, supply chain, forged keys',
  },
  {
    type: 'container_url',
    icon: Link,
    label: 'Link to Container Image',
    description: 'Download and scan a container image tar from a URL',
  },
];

const networkModes: Array<{
  value: NetworkMode;
  label: string;
  description: string;
}> = [
  {
    value: 'isolated',
    label: 'Isolated (default)',
    description: 'No network access - safest option',
  },
  {
    value: 'simulated',
    label: 'Simulated Internet',
    description: 'FakeNet responses to observe C2 behavior',
  },
  {
    value: 'controlled',
    label: 'Controlled Internet',
    description: 'Real internet with monitoring - use with caution',
  },
];

const timeoutOptions = [
  { value: 30, label: '30s' },
  { value: 60, label: '60s' },
  { value: 120, label: '2m' },
  { value: 300, label: '5m' },
];

export function SubmitPage() {
  const [type, setType] = useState<SubmissionType>('file');
  const [file, setFile] = useState<File | null>(null);
  const [url, setUrl] = useState('');
  const [dragActive, setDragActive] = useState(false);
  const [submitting, setSubmitting] = useState(false);
  const [error, setError] = useState('');
  const [networkMode, setNetworkMode] = useState<NetworkMode>('isolated');
  const [timeout, setTimeout] = useState<number>(120);
  const navigate = useNavigate();

  const handleDrag = useCallback((e: React.DragEvent) => {
    e.preventDefault();
    e.stopPropagation();
    if (e.type === 'dragenter' || e.type === 'dragover') {
      setDragActive(true);
    } else if (e.type === 'dragleave') {
      setDragActive(false);
    }
  }, []);

  const handleDrop = useCallback((e: React.DragEvent) => {
    e.preventDefault();
    e.stopPropagation();
    setDragActive(false);
    if (e.dataTransfer.files?.[0]) {
      setFile(e.dataTransfer.files[0]);
    }
  }, []);

  const handleSubmit = async (e: FormEvent) => {
    e.preventDefault();
    setError('');
    setSubmitting(true);
    try {
      if (type === 'file' || type === 'email' || type === 'container') {
        if (!file) {
          setError('Please select a file');
          return;
        }
        const formData = new FormData();
        formData.append('file', file);
        formData.append('type', type);
        formData.append('networkMode', networkMode);
        formData.append('timeout', String(timeout));
        const res = await api.post('/submissions/upload', formData, {
          headers: { 'Content-Type': 'multipart/form-data' },
        });
        navigate(`/submissions/${res.data.data.id}`);
      } else if (type === 'url' || type === 'container_url') {
        if (!url) {
          setError('Please enter a URL');
          return;
        }
        const res = await api.post('/submissions', {
          type: 'url',
          url,
          workflow: type === 'container_url' ? 'container' : 'default',
        });
        navigate(`/submissions/${res.data.data.id}`);
      }
    } catch (err: unknown) {
      const message =
        err instanceof Error ? err.message : 'Submission failed';
      setError(message);
    } finally {
      setSubmitting(false);
    }
  };

  return (
    <div className="p-4 md:p-8 max-w-4xl mx-auto">
      <div className="mb-6 md:mb-8">
        <h1 className="text-2xl font-bold text-white">Submit Sample</h1>
        <p className="text-gray-400 mt-1">
          Upload a suspicious file, URL, email, or container for analysis
        </p>
      </div>

      <div className="grid grid-cols-2 md:grid-cols-4 gap-4 mb-8">
        {submissionTypes.map(({ type: t, icon: Icon, label, description }) => (
          <button
            key={t}
            onClick={() => {
              setType(t);
              setFile(null);
              setUrl('');
              setError('');
            }}
            className={clsx(
              'p-4 rounded-xl border text-left transition-all',
              type === t
                ? 'bg-scanboy-600/10 border-scanboy-600 ring-1 ring-scanboy-600'
                : 'bg-gray-900 border-gray-800 hover:border-gray-700',
            )}
          >
            <Icon
              className={clsx(
                'w-6 h-6 mb-2',
                type === t ? 'text-scanboy-400' : 'text-gray-500',
              )}
            />
            <p className="text-sm font-medium text-white">{label}</p>
            <p className="text-xs text-gray-500 mt-1">{description}</p>
          </button>
        ))}
      </div>

      {error && (
        <div className="flex items-center gap-2 p-3 mb-6 bg-red-900/30 border border-red-800 rounded-lg text-red-400 text-sm">
          <AlertCircle className="w-4 h-4 shrink-0" />
          {error}
        </div>
      )}

      <form onSubmit={handleSubmit}>
        {(type === 'file' || type === 'email' || type === 'container') && (
          <div
            onDragEnter={handleDrag}
            onDragLeave={handleDrag}
            onDragOver={handleDrag}
            onDrop={handleDrop}
            className={clsx(
              'relative border-2 border-dashed rounded-xl p-12 text-center transition-colors',
              dragActive
                ? 'border-scanboy-500 bg-scanboy-600/10'
                : file
                  ? 'border-green-600 bg-green-900/10'
                  : 'border-gray-700 hover:border-gray-600',
            )}
          >
            {file ? (
              <div className="flex items-center justify-center gap-3">
                <File className="w-8 h-8 text-green-400" />
                <div className="text-left">
                  <p className="text-white font-medium">{file.name}</p>
                  <p className="text-sm text-gray-400">
                    {(file.size / 1024 / 1024).toFixed(2)} MB
                  </p>
                </div>
                <button
                  type="button"
                  onClick={() => setFile(null)}
                  className="p-1 text-gray-400 hover:text-red-400"
                >
                  <X className="w-5 h-5" />
                </button>
              </div>
            ) : (
              <label className="cursor-pointer block">
                <Upload className="w-12 h-12 text-gray-500 mx-auto mb-4" />
                <p className="text-white font-medium">
                  Drop file here or click to browse
                </p>
                <p className="text-sm text-gray-500 mt-2">
                  Maximum file size: 500 MB
                </p>
                <input
                  type="file"
                  onChange={(e) =>
                    e.target.files?.[0] && setFile(e.target.files[0])
                  }
                  className="hidden"
                />
              </label>
            )}
          </div>
        )}

        {(type === 'url' || type === 'container_url') && (
          <div>
            <label className="block text-sm font-medium text-gray-300 mb-2">
              URL to analyze
            </label>
            <input
              type="url"
              value={url}
              onChange={(e) => setUrl(e.target.value)}
              placeholder="https://suspicious-site.example.com/payload"
              className="w-full px-4 py-3 bg-gray-900 border border-gray-700 rounded-lg text-white placeholder-gray-500 focus:outline-none focus:ring-2 focus:ring-scanboy-500"
              required
            />
          </div>
        )}

        {/* Analysis Options */}
        <div className="mt-8 bg-gray-900 border border-gray-800 rounded-xl p-6">
          <div className="flex items-center gap-2 mb-4">
            <Settings className="w-5 h-5 text-gray-400" />
            <h3 className="text-md font-semibold text-white">Analysis Options</h3>
          </div>

          <div className="grid grid-cols-1 md:grid-cols-2 gap-6">
            {/* Network Mode */}
            <div>
              <label className="block text-sm font-medium text-gray-300 mb-2">
                Network Mode
              </label>
              <select
                value={networkMode}
                onChange={(e) => setNetworkMode(e.target.value as NetworkMode)}
                className="w-full px-4 py-2.5 bg-gray-800 border border-gray-700 rounded-lg text-white focus:outline-none focus:ring-2 focus:ring-scanboy-500 appearance-none"
              >
                {networkModes.map((mode) => (
                  <option key={mode.value} value={mode.value}>
                    {mode.label}
                  </option>
                ))}
              </select>
              <p className="text-xs text-gray-500 mt-1.5">
                {networkModes.find((m) => m.value === networkMode)?.description}
              </p>
            </div>

            {/* Timeout */}
            <div>
              <label className="block text-sm font-medium text-gray-300 mb-2">
                Execution Timeout
              </label>
              <div className="flex items-center gap-1">
                {timeoutOptions.map((opt) => (
                  <button
                    key={opt.value}
                    type="button"
                    onClick={() => setTimeout(opt.value)}
                    className={clsx(
                      'flex-1 py-2.5 px-3 rounded-lg text-sm font-medium transition-all border',
                      timeout === opt.value
                        ? 'bg-scanboy-600/20 border-scanboy-600 text-scanboy-400'
                        : 'bg-gray-800 border-gray-700 text-gray-400 hover:border-gray-600',
                    )}
                  >
                    {opt.label}
                  </button>
                ))}
              </div>
              <p className="text-xs text-gray-500 mt-1.5">
                Maximum time for sample execution before termination
              </p>
            </div>
          </div>

          {networkMode === 'controlled' && (
            <div className="mt-4 flex items-center gap-2 p-3 bg-yellow-900/20 border border-yellow-800/50 rounded-lg text-yellow-400 text-xs">
              <AlertCircle className="w-4 h-4 shrink-0" />
              <span>
                Controlled internet allows the sample to make real network connections.
                Use only in isolated environments with proper monitoring.
              </span>
            </div>
          )}
        </div>

        <button
          type="submit"
          disabled={submitting}
          className="mt-6 w-full py-3 bg-scanboy-600 hover:bg-scanboy-700 disabled:opacity-50 text-white font-medium rounded-lg transition-colors"
        >
          {submitting ? 'Submitting...' : 'Submit for Analysis'}
        </button>
      </form>
    </div>
  );
}
