const JOB_STATUS: Record<string, string> = {
  queued: "в очереди",
  running: "идёт",
  success: "готово",
  failed: "ошибка",
};

export function jobStatusLabel(status: string): string {
  return JOB_STATUS[status] ?? status;
}

function pad(n: number): string {
  return String(n).padStart(2, "0");
}

function parseInstant(value: string | null | undefined): Date | null {
  if (!value || !String(value).trim()) return null;
  const d = new Date(value);
  return Number.isNaN(d.getTime()) ? null : d;
}

/** Local calendar date: DD.MM.YYYY */
export function formatDate(value: string | null | undefined): string {
  const d = parseInstant(value);
  if (!d) return "—";
  return `${pad(d.getDate())}.${pad(d.getMonth() + 1)}.${d.getFullYear()}`;
}

/** Local clock: HH:mm */
export function formatTime(value: string | null | undefined): string {
  const d = parseInstant(value);
  if (!d) return "—";
  return `${pad(d.getHours())}:${pad(d.getMinutes())}`;
}

