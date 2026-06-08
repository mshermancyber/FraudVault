import { useQuery } from '@tanstack/react-query';
import { api } from '@/lib/api';
import {
  FileSearch,
  AlertTriangle,
  Shield,
  Clock,
  TrendingUp,
  Bug,
  Activity,
  Skull,
} from 'lucide-react';
import { useNavigate } from 'react-router-dom';

interface DashboardStats {
  totalSubmissions: number;
  activeAnalyses: number;
  threatsDetected: number;
  pendingReview: number;
  recentSubmissions: Array<{
    id: string;
    filename: string;
    threatLevel: string;
    status: string;
    createdAt: string;
  }>;
}

interface DashboardTrends {
  submissionsByDay: Array<{ date: string; count: number }>;
  threatDistribution: Array<{ level: string; count: number }>;
  topFamilies: Array<{ name: string; count: number }>;
  recentCritical: Array<{
    id: string;
    filename: string;
    threatLevel: string;
    family: string;
  }>;
}

function StatCard({
  icon: Icon,
  label,
  value,
  color,
}: {
  icon: typeof FileSearch;
  label: string;
  value: number | string;
  color: string;
}) {
  return (
    <div className="bg-gray-900 border border-gray-800 rounded-xl p-4 md:p-6">
      <div className="flex items-center justify-between">
        <div className="min-w-0">
          <p className="text-xs md:text-sm text-gray-400 truncate">{label}</p>
          <p className="text-xl md:text-3xl font-bold text-white mt-1">{value}</p>
        </div>
        <div className={`p-2 md:p-3 rounded-lg ${color} shrink-0`}>
          <Icon className="w-5 h-5 md:w-6 md:h-6" />
        </div>
      </div>
    </div>
  );
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
    analyzing: 'text-blue-400',
    review: 'text-yellow-400',
    confirmed_malicious: 'text-red-400',
    benign: 'text-green-400',
    submitted: 'text-gray-400',
    queued: 'text-gray-400',
  };
  return (
    <span className={`text-xs font-medium ${colors[status] ?? 'text-gray-400'}`}>
      {status.replace('_', ' ')}
    </span>
  );
}

const THREAT_LEVEL_COLORS: Record<string, string> = {
  critical: 'bg-red-500',
  high: 'bg-orange-500',
  medium: 'bg-yellow-500',
  low: 'bg-blue-500',
  informational: 'bg-gray-500',
};

function SubmissionsByDayChart({ data }: { data: Array<{ date: string; count: number }> }) {
  const maxCount = Math.max(...data.map((d) => d.count), 1);

  return (
    <div className="flex items-end gap-2 h-32">
      {data.map((day) => {
        const height = Math.max((day.count / maxCount) * 100, 4);
        const dateLabel = new Date(day.date).toLocaleDateString(undefined, {
          weekday: 'short',
        });
        return (
          <div key={day.date} className="flex-1 flex flex-col items-center gap-1">
            <span className="text-xs text-gray-500">{day.count}</span>
            <div
              className="w-full bg-scanboy-500 rounded-t transition-all"
              style={{ height: `${height}%` }}
            />
            <span className="text-xs text-gray-500">{dateLabel}</span>
          </div>
        );
      })}
    </div>
  );
}

function ThreatDistributionChart({
  data,
}: {
  data: Array<{ level: string; count: number }>;
}) {
  const maxCount = Math.max(...data.map((d) => d.count), 1);
  const levels = ['critical', 'high', 'medium', 'low', 'informational'];

  // Order by severity
  const orderedData = levels.map((level) => {
    const found = data.find((d) => d.level === level);
    return { level, count: found?.count ?? 0 };
  });

  return (
    <div className="space-y-3">
      {orderedData.map(({ level, count }) => {
        const width = maxCount > 0 ? (count / maxCount) * 100 : 0;
        return (
          <div key={level} className="flex items-center gap-3">
            <ThreatBadge level={level} />
            <div className="flex-1 h-3 bg-gray-800 rounded-full overflow-hidden">
              <div
                className={`h-full rounded-full transition-all ${THREAT_LEVEL_COLORS[level] ?? 'bg-gray-600'}`}
                style={{ width: `${Math.max(width, 0)}%` }}
              />
            </div>
            <span className="text-sm text-gray-400 w-8 text-right">{count}</span>
          </div>
        );
      })}
    </div>
  );
}

function TopFamiliesList({ data }: { data: Array<{ name: string; count: number }> }) {
  const maxCount = Math.max(...data.map((d) => d.count), 1);

  if (data.length === 0) {
    return (
      <div className="text-center text-gray-500 py-4">
        <p className="text-sm">No malware families detected yet</p>
      </div>
    );
  }

  return (
    <div className="space-y-2">
      {data.map(({ name, count }) => {
        const width = (count / maxCount) * 100;
        return (
          <div key={name} className="flex items-center gap-3">
            <span className="text-sm text-gray-300 w-32 truncate" title={name}>
              {name}
            </span>
            <div className="flex-1 h-2 bg-gray-800 rounded-full overflow-hidden">
              <div
                className="h-full bg-red-500 rounded-full"
                style={{ width: `${width}%` }}
              />
            </div>
            <span className="text-xs text-gray-500 w-6 text-right">{count}</span>
          </div>
        );
      })}
    </div>
  );
}

function RecentCriticalList({
  data,
}: {
  data: Array<{ id: string; filename: string; threatLevel: string; family: string }>;
}) {
  const navigate = useNavigate();

  if (data.length === 0) {
    return (
      <div className="text-center text-gray-500 py-4">
        <Shield className="w-8 h-8 mx-auto mb-2 opacity-30" />
        <p className="text-sm">No critical/high threats detected</p>
      </div>
    );
  }

  return (
    <div className="divide-y divide-gray-800">
      {data.map((item) => (
        <button
          key={item.id}
          onClick={() => navigate(`/submissions/${item.id}`)}
          className="w-full px-4 py-3 flex items-center justify-between hover:bg-gray-800/50 transition-colors text-left"
        >
          <div className="min-w-0 flex-1">
            <p className="text-sm font-medium text-white truncate">
              {item.filename}
            </p>
            {item.family && (
              <p className="text-xs text-gray-500 mt-0.5">{item.family}</p>
            )}
          </div>
          <ThreatBadge level={item.threatLevel} />
        </button>
      ))}
    </div>
  );
}

function RecentDetectionsFeed({
  submissions,
}: {
  submissions: Array<{
    id: string;
    filename: string;
    threatLevel: string;
    status: string;
    createdAt: string;
  }>;
}) {
  const navigate = useNavigate();
  const threats = submissions.filter(
    (s) => s.threatLevel !== 'informational' && s.threatLevel !== 'low',
  );

  if (threats.length === 0) {
    return (
      <div className="text-center text-gray-500 py-6">
        <Shield className="w-10 h-10 mx-auto mb-2 opacity-30" />
        <p className="text-sm">No recent threat detections</p>
        <p className="text-xs mt-1 text-gray-600">
          Submit samples to populate the threat feed
        </p>
      </div>
    );
  }

  return (
    <div className="divide-y divide-gray-800">
      {threats.slice(0, 8).map((item) => (
        <button
          key={item.id}
          onClick={() => navigate(`/submissions/${item.id}`)}
          className="w-full px-4 py-3 flex items-center gap-3 hover:bg-gray-800/50 transition-colors text-left"
        >
          <Skull className="w-4 h-4 text-red-400 shrink-0" />
          <div className="min-w-0 flex-1">
            <p className="text-sm text-white truncate">{item.filename}</p>
            <p className="text-xs text-gray-500">
              {new Date(item.createdAt).toLocaleString()}
            </p>
          </div>
          <ThreatBadge level={item.threatLevel} />
        </button>
      ))}
    </div>
  );
}

export function DashboardPage() {
  const { data: stats } = useQuery<DashboardStats>({
    queryKey: ['dashboard-stats'],
    queryFn: async () => {
      const res = await api.get('/dashboard/stats');
      return res.data.data;
    },
  });

  const { data: trends } = useQuery<DashboardTrends>({
    queryKey: ['dashboard-trends'],
    queryFn: async () => {
      const res = await api.get('/dashboard/trends');
      return res.data.data;
    },
  });

  const displayStats = stats ?? {
    totalSubmissions: 0,
    activeAnalyses: 0,
    threatsDetected: 0,
    pendingReview: 0,
    recentSubmissions: [],
  };

  const displayTrends = trends ?? {
    submissionsByDay: [],
    threatDistribution: [],
    topFamilies: [],
    recentCritical: [],
  };

  return (
    <div className="p-4 md:p-8">
      <div className="mb-8">
        <h1 className="text-2xl font-bold text-white">Dashboard</h1>
        <p className="text-gray-400 mt-1">
          Malware analysis overview and recent activity
        </p>
      </div>

      <div className="grid grid-cols-2 md:grid-cols-2 lg:grid-cols-4 gap-3 md:gap-6 mb-6 md:mb-8">
        <StatCard
          icon={FileSearch}
          label="Total Submissions"
          value={displayStats.totalSubmissions}
          color="bg-scanboy-600/20 text-scanboy-400"
        />
        <StatCard
          icon={Clock}
          label="Active Analyses"
          value={displayStats.activeAnalyses}
          color="bg-blue-600/20 text-blue-400"
        />
        <StatCard
          icon={AlertTriangle}
          label="Threats Detected"
          value={displayStats.threatsDetected}
          color="bg-red-600/20 text-red-400"
        />
        <StatCard
          icon={Shield}
          label="Pending Review"
          value={displayStats.pendingReview}
          color="bg-yellow-600/20 text-yellow-400"
        />
      </div>

      {/* Trends Row: Submissions by Day + Threat Distribution */}
      <div className="grid grid-cols-1 lg:grid-cols-2 gap-4 md:gap-6 mb-6 md:mb-8">
        <div className="bg-gray-900 border border-gray-800 rounded-xl">
          <div className="px-4 md:px-6 py-3 md:py-4 border-b border-gray-800 flex items-center gap-2">
            <Activity className="w-5 h-5 text-gray-400" />
            <h2 className="text-base md:text-lg font-semibold text-white">
              Submissions (Last 7 Days)
            </h2>
          </div>
          <div className="p-6">
            {displayTrends.submissionsByDay.length > 0 ? (
              <SubmissionsByDayChart data={displayTrends.submissionsByDay} />
            ) : (
              <div className="h-32 flex items-center justify-center text-gray-500 text-sm">
                No submission data yet
              </div>
            )}
          </div>
        </div>

        <div className="bg-gray-900 border border-gray-800 rounded-xl">
          <div className="px-6 py-4 border-b border-gray-800 flex items-center gap-2">
            <Shield className="w-5 h-5 text-gray-400" />
            <h2 className="text-lg font-semibold text-white">
              Threat Distribution
            </h2>
          </div>
          <div className="p-6">
            <ThreatDistributionChart data={displayTrends.threatDistribution} />
          </div>
        </div>
      </div>

      {/* Second Row: Top Families + Recent Critical */}
      <div className="grid grid-cols-1 lg:grid-cols-2 gap-4 md:gap-6 mb-6 md:mb-8">
        <div className="bg-gray-900 border border-gray-800 rounded-xl">
          <div className="px-6 py-4 border-b border-gray-800 flex items-center gap-2">
            <Bug className="w-5 h-5 text-gray-400" />
            <h2 className="text-lg font-semibold text-white">
              Top Malware Families
            </h2>
          </div>
          <div className="p-6">
            <TopFamiliesList data={displayTrends.topFamilies} />
          </div>
        </div>

        <div className="bg-gray-900 border border-gray-800 rounded-xl">
          <div className="px-6 py-4 border-b border-gray-800 flex items-center gap-2">
            <AlertTriangle className="w-5 h-5 text-red-400" />
            <h2 className="text-lg font-semibold text-white">
              Recent Critical/High Threats
            </h2>
          </div>
          <RecentCriticalList data={displayTrends.recentCritical} />
        </div>
      </div>

      {/* Third Row: Recent Submissions + Threat Feed */}
      <div className="grid grid-cols-1 lg:grid-cols-2 gap-4 md:gap-6">
        <div className="bg-gray-900 border border-gray-800 rounded-xl">
          <div className="px-6 py-4 border-b border-gray-800 flex items-center gap-2">
            <TrendingUp className="w-5 h-5 text-gray-400" />
            <h2 className="text-lg font-semibold text-white">
              Recent Submissions
            </h2>
          </div>
          <div className="divide-y divide-gray-800">
            {displayStats.recentSubmissions.length === 0 ? (
              <div className="p-8 text-center text-gray-500">
                <Bug className="w-12 h-12 mx-auto mb-3 opacity-30" />
                <p>No submissions yet</p>
                <p className="text-sm mt-1">Upload a sample to get started</p>
              </div>
            ) : (
              displayStats.recentSubmissions.map((sub) => (
                <div
                  key={sub.id}
                  className="px-6 py-3 flex items-center justify-between hover:bg-gray-800/50 transition-colors"
                >
                  <div className="min-w-0">
                    <p className="text-sm font-medium text-white truncate">
                      {sub.filename}
                    </p>
                    <p className="text-xs text-gray-500">
                      {new Date(sub.createdAt).toLocaleString()}
                    </p>
                  </div>
                  <div className="flex items-center gap-3">
                    <StatusBadge status={sub.status} />
                    <ThreatBadge level={sub.threatLevel} />
                  </div>
                </div>
              ))
            )}
          </div>
        </div>

        <div className="bg-gray-900 border border-gray-800 rounded-xl">
          <div className="px-6 py-4 border-b border-gray-800 flex items-center gap-2">
            <Skull className="w-5 h-5 text-red-400" />
            <h2 className="text-lg font-semibold text-white">
              Threat Feed
            </h2>
            <span className="ml-auto text-xs text-gray-600">Recent detections</span>
          </div>
          <RecentDetectionsFeed submissions={displayStats.recentSubmissions} />
        </div>
      </div>
    </div>
  );
}
