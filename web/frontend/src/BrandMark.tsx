/** Flat 2D hex in the Sonatype/Nexus palette — original geometry, not their mark. */
export default function BrandMark({ className }: { className?: string }) {
  return (
    <svg
      className={className}
      viewBox="0 0 32 32"
      xmlns="http://www.w3.org/2000/svg"
      aria-hidden
    >
      <path fill="#47D5CF" d="M16 2.4 27.6 9.1 16 15.8 4.4 9.1Z" />
      <path fill="#0E7C78" d="M4.4 9.1 16 15.8v13.4L4.4 22.5Z" />
      <path fill="#F08C2A" d="M27.6 9.1 16 15.8v13.4l11.6-6.7Z" />
    </svg>
  );
}
