import type { BillingLine } from '../../lib/billing';

export function Lines({ lines, format, label }: { lines: BillingLine[]; format: (amount: number) => string; label: string }) {
  return <div className="table-scroll" role="region" tabIndex={0} aria-labelledby={label}>
    <table aria-labelledby={label} className="report-table billing-lines">
      <thead><tr><th>Description</th><th>Quantity</th><th>Unit price</th><th>Factor</th><th>Amount</th></tr></thead>
      <tbody>{lines.map((line, index) => <tr key={index}>
        <th scope="row">{line.description}</th><td>{line.quantity}</td><td>{format(line.unitAmount)}</td>
        <td>{line.numerator === line.denominator ? '1' : `${line.numerator}/${line.denominator}`}</td><td>{format(line.amount)}</td>
      </tr>)}</tbody>
    </table>
  </div>;
}

export function Totals({ subtotal, tax, total, taxLabel, format }: {
  subtotal: number; tax: number; total: number; taxLabel: string; format: (amount: number) => string;
}) {
  return <dl className="billing-totals">
    <div><dt>Subtotal</dt><dd>{format(subtotal)}</dd></div>
    <div><dt>{taxLabel}</dt><dd>{format(tax)}</dd></div>
    <div><dt>Total</dt><dd className="emphasis">{format(total)}</dd></div>
  </dl>;
}
