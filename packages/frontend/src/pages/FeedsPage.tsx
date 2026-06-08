import { useQuery, useMutation, useQueryClient } from '@tanstack/react-query';
import { api } from '@/lib/api';
import {
  Database,
  RefreshCw,
  CheckCircle,
  XCircle,
  Clock,
  AlertTriangle,
  Loader2,
} from 'lucide-react';
import { clsx } from 'clsx';

interface FeedInfo {
  name: string;
  updatedAt: string | null;
  rowCount: number;
  status: string;
  detail: string | null;
}

interface FeedsStatus {
  feeds: FeedInfo[];
  scheduler: {
    dailyAt: string;
    nextRun: string;
  };
}

const FEED_LABELS: Record<string, { label: string; description: string }> = {
  kev: {
    label: 'CISA KEV',
    description: 'Known Exploited Vulnerabilities catalog',
  },
  epss: {
    label: 'EPSS',
    description: 'Exploit Prediction Scoring System (daily scores)',
  },
  nvd: {
    label: 'NVD / cvelistV5',
    description: 'Full CVE corpus from MITRE (354k+ records)',
  },
  osv: {
    label: 'OSV',
    description: 'Open Source Vulnerabilities (per-ecosystem mirrors)',
  },
  enriched: {
    label: 'Enriched',
    description: 'Joined table: KEV + EPSS + NVD in one lookup',
  },
  cpe_match: {
    label: 'CPE Match',
    description: 'CPE-to-CVE mapping for version-based lookups',
  },
  endoflife: {
    label: 'End-of-Life',
    description: 'Software version lifecycle data from endoflife.date',
  },
  yara_rules: {
    label: 'YARA Rules',
    description: 'Public YARA rules from signature-base, YARA-Rules, ReversingLabs, bartblaze (weekly)',
  },
};

function StatusIcon({ status }: { status: string }) {
  switch (status) {
    case 'ready':
      return <CheckCircle className="w-5 h-5 text-green-400" />;
    case 'refreshing':
      return <Loader2 className="w-5 h-5 text-blue-400 animate-spin" />;
    case 'error':
      return <XCircle className="w-5 h-5 text-red-400" />;
    case 'empty':
      return <Clock className="w-5 h-5 text-gray-500" />;
    default:
      return <AlertTriangle className="w-5 h-5 text-yellow-400" />;
  }
}

function StatusBadge({ status }: { status: string }) {
  const colors: Record<string, string> = {
    ready: 'bg-green-900/30 text-green-400 border-green-800/50',
    refreshing: 'bg-blue-900/30 text-blue-400 border-blue-800/50',
    error: 'bg-red-900/30 text-red-400 border-red-800/50',
    empty: 'bg-gray-800 text-gray-500 border-gray-700',
  };
  return (
    <span className={clsx('px-2 py-0.5 text-xs font-medium rounded border', colors[status] ?? colors['empty'])}>
      {status}
    </span>
  );
}

function formatNumber(n: number): string {
  if (n >= 1_000_000) return `${(n / 1_000_000).toFixed(1)}M`;
  if (n >= 1_000) return `${(n / 1_000).toFixed(1)}K`;
  return String(n);
}

function timeAgo(dateStr: string): string {
  const diff = Date.now() - new Date(dateStr).getTime();
  const mins = Math.floor(diff / 60_000);
  if (mins < 1) return 'just now';
  if (mins < 60) return `${mins}m ago`;
  const hours = Math.floor(mins / 60);
  if (hours < 24) return `${hours}h ago`;
  const days = Math.floor(hours / 24);
  return `${days}d ago`;
}

export function FeedsPage() {
  const queryClient = useQueryClient();

  const { data, isLoading, error } = useQuery<FeedsStatus>({
    queryKey: ['feeds-status'],
    queryFn: async () => {
      const res = await api.get('/feeds/status');
      return res.data;
    },
    refetchInterval: 10_000,
  });

  const refreshMutation = useMutation({
    mutationFn: async (feed: string) => {
      await api.post(`/feeds/refresh?feed=${feed}`);
    },
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ['feeds-status'] });
    },
  });

  const feeds = data?.feeds ?? [];
  const scheduler = data?.scheduler;
  const totalRecords = feeds.reduce((sum, f) => sum + f.rowCount, 0);
  const readyCount = feeds.filter(f => f.status === 'ready').length;
  const errorCount = feeds.filter(f => f.status === 'error').length;

  return (
    <div className="p-4 md:p-8">
      <div className="mb-6 md:mb-8">
        <div className="flex items-center justify-between">
          <div>
            <div className="flex items-center gap-2 mb-2">
              <Database className="w-6 h-6 text-scanboy-500" />
              <h1 className="text-2xl font-bold text-white">Vulnerability Feeds</h1>
            </div>
            <p className="text-gray-400">
              Offline vulnerability data for CVE enrichment, KEV, EPSS, and CPE matching
            </p>
          </div>
          <button
            onClick={() => refreshMutation.mutate('all')}
            disabled={refreshMutation.isPending}
            className="inline-flex items-center gap-2 px-4 py-2 bg-scanboy-600 hover:bg-scanboy-700 disabled:opacity-50 text-white text-sm font-medium rounded-lg transition-colors"
          >
            <RefreshCw className={clsx('w-4 h-4', refreshMutation.isPending && 'animate-spin')} />
            {refreshMutation.isPending ? 'Refreshing...' : 'Refresh All'}
          </button>
        </div>
      </div>

      {/* Summary Cards */}
      <div className="grid grid-cols-1 md:grid-cols-4 gap-4 mb-8">
        <div className="bg-gray-900 border border-gray-800 rounded-xl p-5">
          <p className="text-sm text-gray-400">Total Records</p>
          <p className="text-3xl font-bold text-white mt-1">{formatNumber(totalRecords)}</p>
        </div>
        <div className="bg-gray-900 border border-gray-800 rounded-xl p-5">
          <p className="text-sm text-gray-400">Feeds Ready</p>
          <p className="text-3xl font-bold text-green-400 mt-1">{readyCount}/{feeds.length}</p>
        </div>
        <div className="bg-gray-900 border border-gray-800 rounded-xl p-5">
          <p className="text-sm text-gray-400">Errors</p>
          <p className={clsx('text-3xl font-bold mt-1', errorCount > 0 ? 'text-red-400' : 'text-gray-500')}>{errorCount}</p>
        </div>
        <div className="bg-gray-900 border border-gray-800 rounded-xl p-5">
          <p className="text-sm text-gray-400">Next Refresh</p>
          <p className="text-lg font-bold text-white mt-1">
            {scheduler?.dailyAt ?? '--:--'}
          </p>
          <p className="text-xs text-gray-500 mt-0.5">daily schedule</p>
        </div>
      </div>

      {/* Loading / Error */}
      {isLoading && (
        <div className="flex items-center justify-center py-12 text-gray-500">
          <Loader2 className="w-6 h-6 animate-spin mr-2" />
          Connecting to feeds service...
        </div>
      )}

      {error && (
        <div className="p-4 bg-red-900/20 border border-red-800/50 rounded-xl mb-6">
          <div className="flex items-center gap-2 text-red-400">
            <XCircle className="w-5 h-5" />
            <span className="font-medium">Feeds service unavailable</span>
          </div>
          <p className="text-sm text-red-300/70 mt-1">
            The vulnerability feeds service is not running. Start it with: docker compose up -d vuln-feeds
          </p>
        </div>
      )}

      {/* Feed Table */}
      {feeds.length > 0 && (
        <div className="bg-gray-900 border border-gray-800 rounded-xl overflow-hidden">
          <table className="w-full">
            <thead>
              <tr className="border-b border-gray-800">
                <th className="px-6 py-3 text-left text-xs font-medium text-gray-400 uppercase tracking-wider">Feed</th>
                <th className="px-6 py-3 text-left text-xs font-medium text-gray-400 uppercase tracking-wider">Status</th>
                <th className="px-6 py-3 text-right text-xs font-medium text-gray-400 uppercase tracking-wider">Records</th>
                <th className="px-6 py-3 text-left text-xs font-medium text-gray-400 uppercase tracking-wider">Last Updated</th>
                <th className="px-6 py-3 text-left text-xs font-medium text-gray-400 uppercase tracking-wider">Detail</th>
                <th className="px-6 py-3 text-right text-xs font-medium text-gray-400 uppercase tracking-wider">Actions</th>
              </tr>
            </thead>
            <tbody className="divide-y divide-gray-800">
              {feeds.map((feed) => {
                const info = FEED_LABELS[feed.name];
                return (
                  <tr key={feed.name} className="hover:bg-gray-800/50 transition-colors">
                    <td className="px-6 py-4">
                      <div className="flex items-center gap-3">
                        <StatusIcon status={feed.status} />
                        <div>
                          <p className="text-sm font-medium text-white">
                            {info?.label ?? feed.name}
                          </p>
                          <p className="text-xs text-gray-500">
                            {info?.description ?? ''}
                          </p>
                        </div>
                      </div>
                    </td>
                    <td className="px-6 py-4">
                      <StatusBadge status={feed.status} />
                    </td>
                    <td className="px-6 py-4 text-right">
                      <span className="text-sm font-mono text-gray-200">
                        {formatNumber(feed.rowCount)}
                      </span>
                    </td>
                    <td className="px-6 py-4">
                      {feed.updatedAt ? (
                        <div>
                          <p className="text-sm text-gray-300">{timeAgo(feed.updatedAt)}</p>
                          <p className="text-xs text-gray-500">
                            {new Date(feed.updatedAt).toLocaleString()}
                          </p>
                        </div>
                      ) : (
                        <span className="text-sm text-gray-600">never</span>
                      )}
                    </td>
                    <td className="px-6 py-4">
                      <p className={clsx(
                        'text-xs truncate max-w-xs',
                        feed.status === 'error' ? 'text-red-400' : 'text-gray-500',
                      )}>
                        {feed.detail ?? '—'}
                      </p>
                    </td>
                    <td className="px-6 py-4 text-right">
                      <button
                        onClick={() => refreshMutation.mutate(feed.name)}
                        disabled={refreshMutation.isPending || feed.status === 'refreshing'}
                        className="inline-flex items-center gap-1 px-2.5 py-1 bg-gray-800 hover:bg-gray-700 disabled:opacity-30 text-gray-300 text-xs font-medium rounded transition-colors"
                      >
                        <RefreshCw className={clsx('w-3 h-3', feed.status === 'refreshing' && 'animate-spin')} />
                        Refresh
                      </button>
                    </td>
                  </tr>
                );
              })}
            </tbody>
          </table>
        </div>
      )}
    </div>
  );
}
