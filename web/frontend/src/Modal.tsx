import { useEffect, useId, useRef, useState, type AnimationEvent, type ReactNode } from "react";
import { createPortal } from "react-dom";

type Props = {
  title: string;
  icon?: ReactNode;
  onClose: () => void;
  children: ReactNode;
};

function reducedMotion() {
  return window.matchMedia("(prefers-reduced-motion: reduce)").matches;
}

export default function Modal({ title, icon, onClose, children }: Props) {
  const titleId = useId();
  const panelRef = useRef<HTMLDivElement>(null);
  const onCloseRef = useRef(onClose);
  const leavingRef = useRef(false);
  onCloseRef.current = onClose;
  const [leaving, setLeaving] = useState(false);

  function requestClose() {
    if (leavingRef.current) return;
    if (reducedMotion()) {
      onCloseRef.current();
      return;
    }
    leavingRef.current = true;
    setLeaving(true);
  }

  useEffect(() => {
    const prev = document.body.style.overflow;
    document.body.style.overflow = "hidden";
    panelRef.current?.focus();
    function onKey(e: KeyboardEvent) {
      if (e.key === "Escape") requestClose();
    }
    document.addEventListener("keydown", onKey);
    return () => {
      document.body.style.overflow = prev;
      document.removeEventListener("keydown", onKey);
    };
  }, []);

  function onBackdropAnimEnd(e: AnimationEvent<HTMLDivElement>) {
    if (e.target !== e.currentTarget) return;
    if (leavingRef.current) onCloseRef.current();
  }

  return createPortal(
    <div
      className={`modal-backdrop${leaving ? " is-leaving" : ""}`}
      onMouseDown={(e) => {
        if (e.target === e.currentTarget) requestClose();
      }}
      onAnimationEnd={onBackdropAnimEnd}
    >
      <div
        ref={panelRef}
        className="modal"
        role="dialog"
        aria-modal="true"
        aria-labelledby={titleId}
        tabIndex={-1}
      >
        <header className="modal-head">
          <div className="modal-head-side">
            {icon ? <span className="modal-icon">{icon}</span> : null}
            <h2 id={titleId}>{title}</h2>
          </div>
          <button type="button" className="modal-close" onClick={requestClose} aria-label="Закрыть">
            <svg width="18" height="18" viewBox="0 0 24 24" fill="none" aria-hidden>
              <path d="M6 6l12 12M18 6L6 18" stroke="currentColor" strokeWidth="1.75" strokeLinecap="round" />
            </svg>
          </button>
        </header>
        {children}
      </div>
    </div>,
    document.body,
  );
}
