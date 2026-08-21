export type Label = {
  id: string;
  name: string;
  color: string;
  description: string;
};

export type Repo = {
  name: string;
  format: string;
  type: string;
  url: string | null;
  support: string;
  labels: Label[];
};

export type Asset = {
  path: string;
  format: string | null;
  file_size: number | null;
  last_modified: string | null;
};

export type Job = {
  id: string;
  repository: string;
  status: string;
  scan_mode: string;
  upload: boolean;
  progress: number;
  progress_text: string;
  error: string;
  exit_code: number | null;
  created_at: string | null;
  started_at: string | null;
  finished_at: string | null;
};

export type Rule = {
  id: string;
  cron: string;
  repos: string[];
  enabled: boolean;
  description: string;
  action: string;
  scan_mode: string;
  last_fire: string;
};

export type HistoryRun = {
  run_id: string;
  repository: string;
  started_at: string;
  finished_at: string | null;
  source: string;
  scanners: string[];
  totals: {
    scanned: number;
    passed: number;
    failed: number;
    errors: number;
    checkpoint_skipped: number;
  };
  rule_id: string | null;
};

export type Status = {
  nexus_url: string;
  username: string;
  counts: { labels: number; jobs: number; schedule_rules: number };
  integrations?: { defectdojo: boolean; webhook: boolean; vk_teams: boolean };
};
