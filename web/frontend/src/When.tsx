import { formatDate, formatTime } from "./format";

export default function When({ value }: { value: string | null | undefined }) {
  const date = formatDate(value);
  if (date === "—") return <span className="when is-empty">—</span>;
  return (
    <span className="when">
      <span className="when-date">{date}</span>
      <span className="when-time">{formatTime(value)}</span>
    </span>
  );
}
