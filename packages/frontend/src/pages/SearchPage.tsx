import { useState, FormEvent } from 'react';
import { useQuery } from '@tanstack/react-query';
import { useNavigate } from 'react-router-dom';
import { api } from '@/lib/api';
import { Search, Filter, ExternalLink, ShieldAlert, ShieldCheck } from 'lucide-react';
import { clsx } from 'clsx';

interface VtData {
  detections: number;
  total: number;
  link: string | null;
  family: string | null;
}

interface SearchResult {
  id: string;
  filename: string;
  sha256: string;
  threatScore: number | null;
  threatLevel: string | null;
  status: string;
  createdAt: string;
  matchField: string;
  matchValue?: string;
  vt?: VtData | null;
}

const searchFields = [
  'all',
  'hash',
  'domain',
  'url',
  'ip',
  'filename',
  'malware_family',
  'attack_technique',
  'registry_key',
];

const levelColors: Record<string, string> = {
  critical: 'bg-red-600 text-white',
  high: 'bg-orange-600 text-white',
  medium: 'bg-yellow-600 text-black',
  low: 'bg-blue-600 text-white',
  informational: 'bg-gray-600 text-white',
};

export function SearchPage() {
  const [query, setQuery] = useState('');
  const [field, setField] = useState('all');
  const [submitted, setSubmitted] = useState(false);
  const navigate = useNavigate();

  const { data: results, isLoading } = useQuery<SearchResult[]>({
    queryKey: ['search', query, field],
    queryFn: async () => {
      const res = await api.get(
        `/search?q=${encodeURIComponent(query)}&field=${field}`,
      );
      return res.data.data;
    },
    enabled: submitted && query.length > 0,
  });

  const handleSearch = (e: FormEvent) => {
    e.preventDefault();
    setSubmitted(true);
  };

  return (
    <div className="p-4 md:p-8">
      <div className="mb-6 md:mb-8">
        <h1 className="text-2xl font-bold text-white">Search</h1>
        <p className="text-gray-400 mt-1">
          Search submissions by hash, domain, IP, filename, or IOC
        </p>
      </div>

      <form onSubmit={handleSearch} className="mb-8">
        <div className="flex gap-4">
          <div className="relative flex-1">
            <Search className="absolute left-3 top-1/2 -translate-y-1/2 w-5 h-5 text-gray-500" />
            <input
              type="text"
              value={query}
              onChange={(e) => {
                setQuery(e.target.value);
                setSubmitted(false);
              }}
              placeholder="Enter hash, domain, IP, filename..."
              className="w-full pl-10 pr-4 py-3 bg-gray-900 border border-gray-700 rounded-lg text-white placeholder-gray-500 focus:outline-none focus:ring-2 focus:ring-scanboy-500"
            />
          </div>
          <div className="relative">
            <Filter className="absolute left-3 top-1/2 -translate-y-1/2 w-4 h-4 text-gray-500" />
            <select
              value={field}
              onChange={(e) => {
                setField(e.target.value);
                setSubmitted(false);
              }}
              className="pl-9 pr-8 py-3 bg-gray-900 border border-gray-700 rounded-lg text-white appearance-none focus:outline-none focus:ring-2 focus:ring-scanboy-500"
            >
              {searchFields.map((f) => (
                <option key={f} value={f}>
                  {f.replace('_', ' ')}
                </option>
              ))}
            </select>
          </div>
          <button
            type="submit"
            className="px-6 py-3 bg-scanboy-600 hover:bg-scanboy-700 text-white font-medium rounded-lg transition-colors"
          >
            Search
          </button>
        </div>
      </form>

      {isLoading && (
        <div className="text-center text-gray-500 py-12">Searching...</div>
      )}

      {results && results.length === 0 && (
        <div className="text-center text-gray-500 py-12">
          <Search className="w-12 h-12 mx-auto mb-3 opacity-30" />
          <p>No results found</p>
        </div>
      )}

      {results && results.length > 0 && (
        <div className="bg-gray-900 border border-gray-800 rounded-xl overflow-hidden">
          <table className="w-full">
            <thead>
              <tr className="border-b border-gray-800">
                <th className="px-4 py-3 text-left text-xs font-medium text-gray-400 uppercase">File</th>
                <th className="px-4 py-3 text-left text-xs font-medium text-gray-400 uppercase">Match</th>
                <th className="px-4 py-3 text-left text-xs font-medium text-gray-400 uppercase">Score</th>
                <th className="px-4 py-3 text-left text-xs font-medium text-gray-400 uppercase">VirusTotal</th>
                <th className="px-4 py-3 text-left text-xs font-medium text-gray-400 uppercase">Date</th>
              </tr>
            </thead>
            <tbody className="divide-y divide-gray-800">
              {results.map((r) => (
                <tr
                  key={r.id}
                  onClick={() => navigate(`/submissions/${r.id}`)}
                  className="hover:bg-gray-800/50 cursor-pointer"
                >
                  <td className="px-4 py-4">
                    <div className="text-sm text-white font-medium">{r.filename}</div>
                    <code className="text-xs text-gray-500 font-mono">{r.sha256?.slice(0, 24)}...</code>
                  </td>
                  <td className="px-4 py-4">
                    <span className="text-xs px-2 py-0.5 rounded bg-scanboy-600/20 text-scanboy-400">
                      {r.matchField}
                    </span>
                    {r.matchValue && r.matchField !== 'filename' && (
                      <div className="text-xs text-gray-500 mt-1 truncate max-w-[200px]" title={r.matchValue}>
                        {r.matchValue}
                      </div>
                    )}
                  </td>
                  <td className="px-4 py-4">
                    {r.threatLevel && (
                      <span className={clsx(
                        'text-xs px-2 py-1 rounded font-bold uppercase',
                        levelColors[r.threatLevel] ?? 'bg-gray-700 text-gray-300',
                      )}>
                        {r.threatScore ?? 0} {r.threatLevel}
                      </span>
                    )}
                  </td>
                  <td className="px-4 py-4">
                    {r.vt ? (
                      <div className="flex items-center gap-2">
                        {r.vt.detections > 0 ? (
                          <ShieldAlert className="w-4 h-4 text-red-400 flex-shrink-0" />
                        ) : (
                          <ShieldCheck className="w-4 h-4 text-green-400 flex-shrink-0" />
                        )}
                        <div>
                          <span className={clsx(
                            'text-xs font-mono font-bold',
                            r.vt.detections > 0 ? 'text-red-400' : 'text-green-400',
                          )}>
                            {r.vt.detections}/{r.vt.total}
                          </span>
                          {r.vt.family && (
                            <span className="text-xs text-orange-400 ml-2">{r.vt.family}</span>
                          )}
                          {r.vt.link && String(r.vt.link).startsWith('https://www.virustotal.com/') && (
                            <a
                              href={r.vt.link}
                              target="_blank"
                              rel="noopener noreferrer"
                              onClick={(e) => e.stopPropagation()}
                              className="inline-flex items-center gap-0.5 ml-2 text-xs text-blue-400 hover:text-blue-300"
                            >
                              VT <ExternalLink className="w-3 h-3" />
                            </a>
                          )}
                        </div>
                      </div>
                    ) : (
                      <span className="text-xs text-gray-600">-</span>
                    )}
                  </td>
                  <td className="px-4 py-4 text-sm text-gray-400 whitespace-nowrap">
                    {new Date(r.createdAt).toLocaleDateString()}
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      )}
    </div>
  );
}
