const JOB_STATUS: Record<string, string> = {
  queued: "в очереди",
  running: "идёт",
  success: "готово",
  failed: "ошибка",
};

export function jobStatusLabel(status: string): string {
  return JOB_STATUS[status] ?? status;
}
