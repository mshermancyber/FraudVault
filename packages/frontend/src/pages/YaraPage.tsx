import { useState } from 'react';
import { useQuery, useMutation, useQueryClient } from '@tanstack/react-query';
import { api } from '@/lib/api';
import {
  Shield,
  Search,
  RefreshCw,
  ChevronDown,
  ChevronRight,
  FileCode,
  Database,
} from 'lucide-react';
import { clsx } from 'clsx';

interface YaraRule {
  name: string;
  source: string;
  ruleText: string;
}

interface YaraStats {
  total: number;
  sources: Array<{ source: string; count: number }>;
}

export function YaraPage() {
  const [search, setSearch] = useState('');
  const [sourceFilter, setSourceFilter] = useState('all');
  const [expandedRule, setExpandedRule] = useState<string | null>(null);
  const queryClient = useQueryClient();

  const { data: stats } = useQuery<YaraStats>({
    queryKey: ['yara-stats'],
    queryFn: async () => {
      const res = await api.get('/feeds/yara/stats');
      return res.data;
    },
  });

  const { data: rules, isLoading } = useQuery<YaraRule[]>({
    queryKey: ['yara-rules'],
    queryFn: async () => {
      const res = await api.get('/feeds/yara/rules');
      return res.data.rules;
    },
  });

  const refreshMutation = useMutation({
    mutationFn: async () => {
      await api.post('/feeds/refresh?feed=yara_rules');
    },
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ['yara-stats'] });
      queryClient.invalidateQueries({ queryKey: ['yara-rules'] });
    },
  });

  const sources = stats?.sources ?? [];
  const allRules = rules ?? [];

  const filtered = allRules.filter(r => {
    if (sourceFilter !== 'all' && r.source !== sourceFilter) return false;
    if (search && !r.name.toLowerCase().includes(search.toLowerCase()) && !r.ruleText.toLowerCase().includes(search.toLowerCase())) return false;
    return true;
  });

  const displayRules = filtered.slice(0, 200);

  return (
    <div className="p-4 md:p-8">
      <div className="flex items-center justify-between mb-6 md:mb-8">
        <div>
          <h1 className="text-2xl font-bold text-white flex items-center gap-3">
            <Shield className="w-7 h-7 text-scanboy-500" />
            YARA Rules
          </h1>
          <p className="text-gray-400 mt-1">
            {stats?.total?.toLocaleString() ?? '...'} rules from {sources.length} sources
          </p>
        </div>
        <button
          onClick={() => refreshMutation.mutate()}
          disabled={refreshMutation.isPending}
          className="flex items-center gap-2 px-4 py-2 bg-scanboy-600 hover:bg-scanboy-700 disabled:opacity-50 text-white text-sm font-medium rounded-lg transition-colors"
        >
          <RefreshCw className={clsx('w-4 h-4', refreshMutation.isPending && 'animate-spin')} />
          {refreshMutation.isPending ? 'Pulling...' : 'Pull Latest'}
        </button>
      </div>

      {/* Source breakdown */}
      <div className="grid grid-cols-2 md:grid-cols-4 gap-4 mb-8">
        {sources.map(s => (
          <button
            key={s.source}
            onClick={() => setSourceFilter(sourceFilter === s.source ? 'all' : s.source)}
            className={clsx(
              'p-4 rounded-xl border transition-colors text-left',
              sourceFilter === s.source
                ? 'bg-scanboy-600/20 border-scanboy-600'
                : 'bg-gray-900 border-gray-800 hover:border-gray-700',
            )}
          >
            <div className="flex items-center gap-2 mb-1">
              <Database className="w-4 h-4 text-gray-500" />
              <span className="text-sm font-medium text-white">{s.source}</span>
            </div>
            <span className="text-2xl font-bold text-scanboy-400">{s.count.toLocaleString()}</span>
            <span className="text-xs text-gray-500 ml-1">rules</span>
          </button>
        ))}
      </div>

      {/* Search */}
      <div className="relative mb-6">
        <Search className="absolute left-3 top-1/2 -translate-y-1/2 w-5 h-5 text-gray-500" />
        <input
          type="text"
          value={search}
          onChange={(e) => setSearch(e.target.value)}
          placeholder="Search rules by name or content..."
          className="w-full pl-10 pr-4 py-3 bg-gray-900 border border-gray-700 rounded-lg text-white placeholder-gray-500 focus:outline-none focus:ring-2 focus:ring-scanboy-500"
        />
        {sourceFilter !== 'all' && (
          <button
            onClick={() => setSourceFilter('all')}
            className="absolute right-3 top-1/2 -translate-y-1/2 text-xs px-2 py-1 bg-scanboy-600/20 text-scanboy-400 rounded"
          >
            {sourceFilter} x
          </button>
        )}
      </div>

      {/* Results */}
      <div className="text-sm text-gray-500 mb-3">
        {filtered.length === allRules.length
          ? `${allRules.length.toLocaleString()} rules`
          : `${filtered.length.toLocaleString()} of ${allRules.length.toLocaleString()} rules`}
        {filtered.length > 200 && ' (showing first 200)'}
      </div>

      {isLoading ? (
        <div className="text-center text-gray-500 py-12">Loading rules...</div>
      ) : (
        <div className="bg-gray-900 border border-gray-800 rounded-xl overflow-hidden divide-y divide-gray-800">
          {displayRules.map((rule) => {
            const isExpanded = expandedRule === `${rule.source}:${rule.name}`;
            return (
              <div key={`${rule.source}:${rule.name}`}>
                <button
                  onClick={() => setExpandedRule(isExpanded ? null : `${rule.source}:${rule.name}`)}
                  className="w-full px-4 py-3 flex items-center gap-3 hover:bg-gray-800/50 transition-colors text-left"
                >
                  {isExpanded ? (
                    <ChevronDown className="w-4 h-4 text-gray-500 flex-shrink-0" />
                  ) : (
                    <ChevronRight className="w-4 h-4 text-gray-500 flex-shrink-0" />
                  )}
                  <FileCode className="w-4 h-4 text-scanboy-500 flex-shrink-0" />
                  <span className="text-sm text-white font-mono flex-1 truncate">{rule.name}</span>
                  <span className="text-xs px-2 py-0.5 rounded bg-gray-800 text-gray-400 flex-shrink-0">
                    {rule.source}
                  </span>
                </button>
                {isExpanded && (
                  <div className="px-4 pb-4">
                    <pre className="bg-gray-950 border border-gray-800 rounded-lg p-4 text-xs text-gray-300 font-mono overflow-x-auto max-h-96 overflow-y-auto whitespace-pre">
                      {rule.ruleText}
                    </pre>
                  </div>
                )}
              </div>
            );
          })}
          {displayRules.length === 0 && (
            <div className="text-center text-gray-500 py-12">
              {search ? 'No rules match your search' : 'No rules loaded'}
            </div>
          )}
        </div>
      )}
    </div>
  );
}
