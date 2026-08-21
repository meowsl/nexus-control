import BrandMark from "./BrandMark";

/** Honeycomb packing — catalog assembling, not a spinner. */
export default function HexLoader({ label = "Собираем каталог" }: { label?: string }) {
  return (
    <div className="hex-loader" role="status" aria-live="polite" aria-label={label}>
      <div className="hex-honeycomb">
        {Array.from({ length: 6 }, (_, i) => (
          <span key={i} className={`hex-cell ring r${i}`}>
            <BrandMark />
          </span>
        ))}
        <span className="hex-cell core">
          <BrandMark />
        </span>
      </div>
      <p className="hex-loader-label">{label}</p>
    </div>
  );
}
