import { useQuery } from '@tanstack/react-query';
import { api } from '@/lib/api';
import { Shield } from 'lucide-react';
import { clsx } from 'clsx';

interface TacticData {
  id: string;
  name: string;
  techniques: Array<{
    id: string;
    name: string;
    count: number;
  }>;
}

const MITRE_TACTICS = [
  { id: 'TA0001', name: 'Initial Access' },
  { id: 'TA0002', name: 'Execution' },
  { id: 'TA0003', name: 'Persistence' },
  { id: 'TA0004', name: 'Privilege Escalation' },
  { id: 'TA0005', name: 'Defense Evasion' },
  { id: 'TA0006', name: 'Credential Access' },
  { id: 'TA0007', name: 'Discovery' },
  { id: 'TA0008', name: 'Lateral Movement' },
  { id: 'TA0009', name: 'Collection' },
  { id: 'TA0010', name: 'Exfiltration' },
  { id: 'TA0011', name: 'Command and Control' },
  { id: 'TA0040', name: 'Impact' },
];

export function AttackMatrixPage() {
  const { data: tactics } = useQuery<TacticData[]>({
    queryKey: ['attack-matrix'],
    queryFn: async () => {
      const res = await api.get('/attack-matrix');
      return res.data.data;
    },
  });

  // Map both MITRE IDs (TA0001) and slug names (initial-access) to tactic data
  const tacticMap = new Map<string, TacticData>();
  const slugToId: Record<string, string> = {
    'reconnaissance': 'TA0043',
    'resource-development': 'TA0042',
    'initial-access': 'TA0001',
    'execution': 'TA0002',
    'persistence': 'TA0003',
    'privilege-escalation': 'TA0004',
    'defense-evasion': 'TA0005',
    'credential-access': 'TA0006',
    'discovery': 'TA0007',
    'lateral-movement': 'TA0008',
    'collection': 'TA0009',
    'exfiltration': 'TA0010',
    'command-and-control': 'TA0011',
    'impact': 'TA0040',
  };
  for (const t of tactics ?? []) {
    tacticMap.set(t.id, t);
    const mappedId = slugToId[t.id];
    if (mappedId) tacticMap.set(mappedId, t);
  }

  return (
    <div className="p-4 md:p-8">
      <div className="mb-6 md:mb-8">
        <div className="flex items-center gap-2 mb-2">
          <Shield className="w-6 h-6 text-scanboy-500" />
          <h1 className="text-2xl font-bold text-white">
            MITRE ATT&CK Matrix
          </h1>
        </div>
        <p className="text-gray-400">
          Techniques observed across all analyzed samples
        </p>
      </div>

      <div className="overflow-x-auto">
        <div className="flex gap-2 min-w-max">
          {MITRE_TACTICS.map((tactic) => {
            const data = tacticMap.get(tactic.id);
            const techniques = data?.techniques ?? [];
            return (
              <div
                key={tactic.id}
                className="w-48 flex-shrink-0"
              >
                <div className="bg-scanboy-600/20 border border-scanboy-600/30 rounded-t-lg px-3 py-2">
                  <p className="text-xs font-medium text-scanboy-300">
                    {tactic.id}
                  </p>
                  <p className="text-sm font-semibold text-white">
                    {tactic.name}
                  </p>
                </div>
                <div className="border-x border-b border-gray-800 rounded-b-lg divide-y divide-gray-800">
                  {techniques.length === 0 ? (
                    <div className="px-3 py-4 text-center text-xs text-gray-600">
                      No observations
                    </div>
                  ) : (
                    techniques.map((tech) => {
                      const TECH_NAMES: Record<string, string> = {
                        'T1027': 'Obfuscated Files or Information',
                        'T1027.002': 'Software Packing',
                        'T1027.005': 'Indicator Removal from Tools',
                        'T1036.008': 'Masquerade File Type',
                        'T1055': 'Process Injection',
                        'T1059': 'Command and Scripting Interpreter',
                        'T1071': 'Application Layer Protocol',
                        'T1071.004': 'DNS',
                        'T1105': 'Ingress Tool Transfer',
                        'T1003': 'OS Credential Dumping',
                        'T1053.003': 'Cron',
                        'T1490': 'Inhibit System Recovery',
                        'T1486': 'Data Encrypted for Impact',
                        'T1547.001': 'Registry Run Keys / Startup',
                      };
                      const techName = TECH_NAMES[tech.id] ?? tech.name;
                      return (
                      <a
                        key={tech.id}
                        href={`https://attack.mitre.org/techniques/${tech.id.replace('.', '/')}/`}
                        target="_blank"
                        rel="noopener noreferrer"
                        className={clsx(
                          'block px-3 py-2 hover:bg-gray-800/50 cursor-pointer transition-colors',
                          tech.count > 5 && 'bg-red-900/10',
                          tech.count > 2 &&
                            tech.count <= 5 &&
                            'bg-yellow-900/10',
                          tech.count >= 1 && tech.count <= 2 && 'bg-scanboy-600/10',
                        )}
                      >
                        <p className="text-xs text-scanboy-400">{tech.id}</p>
                        <p className="text-sm text-gray-200">{techName}</p>
                        <p className="text-xs text-gray-500 mt-1">
                          {tech.count} sample{tech.count !== 1 ? 's' : ''}
                        </p>
                      </a>
                    );})

                  )}
                </div>
              </div>
            );
          })}
        </div>
      </div>
    </div>
  );
}
