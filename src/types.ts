export interface SecurityCheck {
  name: string;
  status: 'pass' | 'fail' | 'warning';
  detail: string;
  tip?: string;
}

export interface ScanResult {
  id?: string;
  domain: string;
  timestamp: string;
  ssl: any;
  headers: any;
  dns: any;
  checks: SecurityCheck[];
  score: number;
}

export const getStatusColor = (status: string) => {
  switch (status) {
    case 'pass': return 'text-emerald-400 border-emerald-500 bg-emerald-500/10';
    case 'warning': return 'text-amber-400 border-amber-500 bg-amber-500/10';
    case 'fail': return 'text-rose-400 border-rose-500 bg-rose-500/10';
    default: return 'text-slate-400 border-slate-500 bg-slate-500/10';
  }
};
