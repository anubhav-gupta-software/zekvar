'use client';

export function PrintButton() {
  return <button type="button" className="button small primary" onClick={() => window.print()}>Print</button>;
}
