import { useQuery } from '@tanstack/react-query';
import { useNavigate, useSearchParams } from 'react-router-dom';
import { api } from '@/lib/api';
import { FileSearch, ChevronLeft, ChevronRight } from 'lucide-react';

interface Submission {
  id: string;
  filename: string;
  fileType: string;
  sha256: string;
  status: string;
  threatLevel: string;
  threatScore: number;
  createdAt: string;
}

interface PaginatedSubmissions {
  items: Submission[];
  total: number;
  page: number;
  pageSize: number;
}

function ThreatBadge({ level }: { level: string }) {
  const colors: Record<string, string> = {
    critical: 'bg-red-900/50 text-red-400 border-red-800',
    high: 'bg-orange-900/50 text-orange-400 border-orange-800',
    medium: 'bg-yellow-900/50 text-yellow-400 border-yellow-800',
    low: 'bg-blue-900/50 text-blue-400 border-blue-800',
    informational: 'bg-gray-800 text-gray-400 border-gray-700',
  };
  return (
    <span
      className={`px-2 py-0.5 text-xs font-medium rounded border ${colors[level] ?? colors.informational}`}
    >
      {level}
    </span>
  );
}

function StatusBadge({ status }: { status: string }) {
  const colors: Record<string, string> = {
    analyzing: 'bg-blue-900/30 text-blue-400',
    review: 'bg-yellow-900/30 text-yellow-400',
    confirmed_malicious: 'bg-red-900/30 text-red-400',
    benign: 'bg-green-900/30 text-green-400',
    submitted: 'bg-gray-800 text-gray-400',
    queued: 'bg-gray-800 text-gray-400',
    escalated: 'bg-purple-900/30 text-purple-400',
    closed: 'bg-gray-800 text-gray-500',
  };
  return (
    <span
      className={`px-2 py-0.5 text-xs font-medium rounded ${colors[status] ?? 'bg-gray-800 text-gray-400'}`}
    >
      {status.replace(/_/g, ' ')}
    </span>
  );
}

export function SubmissionsPage() {
  const [searchParams, setSearchParams] = useSearchParams();
  const rawPage = parseInt(searchParams.get('page') ?? '1', 10);
  const page = Number.isFinite(rawPage) && rawPage >= 1 ? rawPage : 1;
  const navigate = useNavigate();

  const { data, isLoading } = useQuery<PaginatedSubmissions>({
    queryKey: ['submissions', page],
    queryFn: async () => {
      const res = await api.get(`/submissions?page=${page}&pageSize=20`);
      return res.data.data;
    },
  });

  const submissions = data?.items ?? [];
  const total = data?.total ?? 0;
  const totalPages = Math.ceil(total / 20);

  return (
    <div className="p-4 md:p-8">
      <div className="mb-6 md:mb-8 flex items-center justify-between">
        <div>
          <h1 className="text-2xl font-bold text-white">Submissions</h1>
          <p className="text-gray-400 mt-1">{total} total submissions</p>
        </div>
      </div>

      {/* Desktop table */}
      <div className="hidden md:block bg-gray-900 border border-gray-800 rounded-xl overflow-hidden">
        <table className="w-full">
          <thead>
            <tr className="border-b border-gray-800">
              <th className="px-6 py-3 text-left text-xs font-medium text-gray-400 uppercase tracking-wider">
                File
              </th>
              <th className="px-6 py-3 text-left text-xs font-medium text-gray-400 uppercase tracking-wider">
                SHA256
              </th>
              <th className="px-6 py-3 text-left text-xs font-medium text-gray-400 uppercase tracking-wider">
                Status
              </th>
              <th className="px-6 py-3 text-left text-xs font-medium text-gray-400 uppercase tracking-wider">
                Threat
              </th>
              <th className="px-6 py-3 text-left text-xs font-medium text-gray-400 uppercase tracking-wider">
                Score
              </th>
              <th className="px-6 py-3 text-left text-xs font-medium text-gray-400 uppercase tracking-wider">
                Submitted
              </th>
            </tr>
          </thead>
          <tbody className="divide-y divide-gray-800">
            {isLoading ? (
              <tr>
                <td colSpan={6} className="px-6 py-12 text-center text-gray-500">
                  Loading...
                </td>
              </tr>
            ) : submissions.length === 0 ? (
              <tr>
                <td colSpan={6} className="px-6 py-12 text-center">
                  <FileSearch className="w-12 h-12 text-gray-600 mx-auto mb-3" />
                  <p className="text-gray-500">No submissions found</p>
                </td>
              </tr>
            ) : (
              submissions.map((sub) => (
                <tr
                  key={sub.id}
                  onClick={() => navigate(`/submissions/${sub.id}`)}
                  className="hover:bg-gray-800/50 cursor-pointer transition-colors"
                >
                  <td className="px-6 py-4">
                    <p className="text-sm font-medium text-white truncate max-w-xs">
                      {sub.filename}
                    </p>
                    <p className="text-xs text-gray-500">{sub.fileType}</p>
                  </td>
                  <td className="px-6 py-4">
                    <code className="text-xs text-gray-400 font-mono">
                      {sub.sha256?.slice(0, 16)}...
                    </code>
                  </td>
                  <td className="px-6 py-4">
                    <StatusBadge status={sub.status} />
                  </td>
                  <td className="px-6 py-4">
                    <ThreatBadge level={sub.threatLevel} />
                  </td>
                  <td className="px-6 py-4">
                    <span className="text-sm text-gray-300">
                      {sub.threatScore}/100
                    </span>
                  </td>
                  <td className="px-6 py-4 text-sm text-gray-400">
                    {new Date(sub.createdAt).toLocaleDateString()}
                  </td>
                </tr>
              ))
            )}
          </tbody>
        </table>
      </div>

      {/* Mobile card list */}
      <div className="md:hidden space-y-3">
        {isLoading ? (
          <div className="py-12 text-center text-gray-500">Loading...</div>
        ) : submissions.length === 0 ? (
          <div className="py-12 text-center">
            <FileSearch className="w-12 h-12 text-gray-600 mx-auto mb-3" />
            <p className="text-gray-500">No submissions found</p>
          </div>
        ) : (
          submissions.map((sub) => (
            <button
              key={sub.id}
              onClick={() => navigate(`/submissions/${sub.id}`)}
              className="w-full text-left bg-gray-900 border border-gray-800 rounded-xl p-4 active:bg-gray-800 transition-colors"
            >
              <div className="flex items-start justify-between gap-2 mb-2">
                <p className="text-sm font-medium text-white truncate flex-1">
                  {sub.filename}
                </p>
                <ThreatBadge level={sub.threatLevel} />
              </div>
              <div className="flex items-center gap-3 flex-wrap">
                <StatusBadge status={sub.status} />
                <span className="text-xs text-gray-400">{sub.threatScore}/100</span>
                <span className="text-xs text-gray-500">
                  {new Date(sub.createdAt).toLocaleDateString()}
                </span>
              </div>
              <code className="text-[10px] text-gray-600 font-mono mt-1.5 block truncate">
                {sub.sha256}
              </code>
            </button>
          ))
        )}
      </div>

      {totalPages > 1 && (
        <div className="mt-4 px-2 md:px-6 py-3 bg-gray-900 border border-gray-800 rounded-xl flex items-center justify-between">
          <p className="text-sm text-gray-400">
            Page {page} of {totalPages}
          </p>
          <div className="flex gap-2">
            <button
              onClick={() =>
                setSearchParams({ page: String(Math.max(1, page - 1)) })
              }
              disabled={page <= 1}
              className="p-2 min-w-[44px] min-h-[44px] flex items-center justify-center rounded bg-gray-800 text-gray-400 active:text-white disabled:opacity-30"
            >
              <ChevronLeft className="w-5 h-5" />
            </button>
            <button
              onClick={() =>
                setSearchParams({
                  page: String(Math.min(totalPages, page + 1)),
                })
              }
              disabled={page >= totalPages}
              className="p-2 min-w-[44px] min-h-[44px] flex items-center justify-center rounded bg-gray-800 text-gray-400 active:text-white disabled:opacity-30"
            >
              <ChevronRight className="w-5 h-5" />
            </button>
          </div>
        </div>
      )}
    </div>
  );
}
