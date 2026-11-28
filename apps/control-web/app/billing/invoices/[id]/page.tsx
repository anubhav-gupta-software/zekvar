import { randomUUID } from 'node:crypto';
import { notFound, redirect } from 'next/navigation';
import { ApiError, controlApi } from '../../../../lib/api';
import { canSeeBilling, lastDay, money, paymentLabels, percent, providerLabels, termLabels } from '../../../../lib/billing';
import { isId, utc } from '../../../../lib/control';
import { sessionToken } from '../../../../lib/session';
import { issueBillingCreditNote, recordBillingPayment, retryBillingSubmission } from '../../../actions';
import { MutationForm } from '../../../forms';
import { Lines, Totals } from '../../lines';
import { PrintButton } from './print-button';

export default async function InvoicePage({ params, searchParams }: {
  params: Promise<{ id: string }>; searchParams: Promise<{ accepted?: string }>;
}) {
  const { accepted } = await searchParams;
  const token = await sessionToken();
  if (!token) redirect('/');
  const { id } = await params;
  if (!isId(id)) notFound();
  const data = await (async () => {
    const session = await controlApi.session(token);
    if (!canSeeBilling(session)) return { session };
    return { session, invoice: await controlApi.billingInvoice(token, id) };
  })().catch((error) => {
    if (error instanceof ApiError && error.status === 401) redirect('/');
    if (error instanceof ApiError && error.status === 404) notFound();
    if (error instanceof ApiError) return undefined;
    throw error;
  });
  const invoice = data?.invoice;
  if (!invoice) return <main className="dashboard"><p className="panel" role="alert">
    {data ? 'Only the organization owner and auditors can view invoices.' : 'Control could not load this invoice.'}</p></main>;
  const owner = data.session.role === 'owner';
  const format = (amount: number) => money(amount, invoice.currency, invoice.minorUnitDigits);
  const credit = invoice.kind === 'credit_note';
  return <main className="dashboard invoice-page">
    <nav className="invoice-actions form-row" aria-label="Invoice actions">
      <a className="button small" href="/billing">Back to billing</a>
      <a className="button small" href={`/billing/invoices/${invoice.id}/export`} download>Download JSON</a>
      <PrintButton />
    </nav>
    {accepted === '1' && <p className="feedback invoice-actions" role="status">Quote accepted. Invoice {invoice.number} was issued.</p>}
    <article className="panel invoice-document" aria-labelledby="invoice-title">
      <header className="invoice-header">
        <div>
          <p className="eyebrow">{credit ? 'Credit note' : 'Invoice'}</p>
          <h1 id="invoice-title">{invoice.number}</h1>
          {credit && invoice.relatedNumber && <p className="muted">Credits invoice {invoice.relatedNumber}</p>}
        </div>
        <span className={`badge ${invoice.paymentStatus === 'paid' ? 'current' : ''}`}>{paymentLabels[invoice.paymentStatus]}</span>
      </header>
      <dl className="billing-facts">
        <div><dt>From</dt><dd>{invoice.issuer.name}{invoice.issuer.detail && <span className="invoice-address">{invoice.issuer.detail}</span>}</dd></div>
        <div><dt>Bill to</dt><dd>{invoice.customer.name}<span className="invoice-address">{invoice.customer.detail}</span></dd></div>
        <div><dt>Issued (UTC)</dt><dd>{utc.format(new Date(invoice.issuedAt))}</dd></div>
        {invoice.dueOn && <div><dt>Due</dt><dd>{invoice.dueOn}</dd></div>}
        <div><dt>Plan</dt><dd>{invoice.planName} · {termLabels[invoice.term]}</dd></div>
        {invoice.periodStart && invoice.periodEnd && <div><dt>Period</dt><dd>{invoice.periodStart} to {lastDay(invoice.periodEnd)}</dd></div>}
      </dl>
      <h2 id="invoice-lines" className="sr-only">Line items</h2>
      <Lines lines={invoice.lines} format={format} label="invoice-lines" />
      <Totals subtotal={invoice.subtotal} tax={invoice.taxAmount} total={invoice.total}
        taxLabel={`${invoice.taxLabel} (${percent(invoice.taxBasisPoints)})`} format={format} />
      {invoice.usage && <p className="muted invoice-note">Usage {invoice.usage.periodStart} to {lastDay(invoice.usage.periodEnd)}: peak
        {' '}{invoice.usage.peakSeats} active seats{invoice.usage.peakDate ? ` on ${invoice.usage.peakDate}` : ''}, {invoice.usage.committedSeats} committed,
        {' '}{invoice.usage.overageSeats} overage. Measured over {invoice.usage.daysMeasured} days.</p>}
      {invoice.note && <p className="muted invoice-note">Reason: {invoice.note}</p>}
      {!credit && <dl className="billing-totals">
        <div><dt>Credited</dt><dd>{format(invoice.creditedTotal)}</dd></div>
        <div><dt>Balance due</dt><dd className="emphasis">{format(invoice.balanceDue)}</dd></div>
      </dl>}
      {invoice.paymentInstructions && invoice.paymentStatus === 'open' && <p className="invoice-note">{invoice.paymentInstructions}
        {' '}Quote {invoice.number} as the payment reference.</p>}
      {invoice.paidAt && <p className="muted invoice-note">Paid {utc.format(new Date(invoice.paidAt))} UTC · Reference {invoice.paymentReference}</p>}
      {!credit && <p className="muted invoice-note">Collection: {providerLabels[invoice.providerStatus]}</p>}
    </article>

    {!credit && invoice.creditNotes.length > 0 && <section className="panel table-panel no-print" aria-labelledby="credit-notes-heading">
      <div className="panel-heading"><h2 id="credit-notes-heading">Credit notes</h2></div>
      <div className="table-scroll" role="region" tabIndex={0} aria-labelledby="credit-notes-heading">
        <table aria-labelledby="credit-notes-heading"><thead><tr><th>Number</th><th>Issued (UTC)</th><th>Total</th></tr></thead>
          <tbody>{invoice.creditNotes.map((note) => <tr key={note.id}>
            <th scope="row"><a className="underline" href={`/billing/invoices/${note.id}`}>{note.number}</a></th>
            <td>{utc.format(new Date(note.issuedAt))}</td><td>{format(note.total)}</td></tr>)}</tbody></table>
      </div>
    </section>}

    {owner && !credit && <section className="panel no-print" aria-labelledby="invoice-manage-heading">
      <h2 id="invoice-manage-heading">Corrections and payment</h2>
      <p className="muted">Issued invoices cannot be edited. Issue a credit note to correct one.</p>
      {invoice.paymentStatus === 'open' && invoice.provider === 'manual' && <MutationForm action={recordBillingPayment} label="Record payment">
        <input type="hidden" name="id" value={invoice.id} />
        <div className="grid gap-1"><label htmlFor="payment-reference">Bank transfer reference</label>
          <input id="payment-reference" name="reference" required maxLength={80} /></div>
      </MutationForm>}
      {invoice.providerStatus === 'failed' && <MutationForm action={retryBillingSubmission} label="Retry provider submission">
        <input type="hidden" name="id" value={invoice.id} />
      </MutationForm>}
      {invoice.total > invoice.creditedTotal && <MutationForm action={issueBillingCreditNote} label="Issue credit note" appearance="danger"
        confirmation="Issue this credit note? Credit notes are numbered and cannot be deleted.">
        <input type="hidden" name="id" value={invoice.id} />
        <input type="hidden" name="requestId" value={randomUUID()} />
        <input type="hidden" name="digits" value={invoice.minorUnitDigits} />
        <div className="grid gap-1"><label htmlFor="credit-amount">Credit before tax ({invoice.currency})</label>
          <input id="credit-amount" name="amount" inputMode="decimal" required pattern="\d+(\.\d+)?" /></div>
        <div className="grid gap-1"><label htmlFor="credit-reason">Reason</label>
          <input id="credit-reason" name="reason" required minLength={3} maxLength={200} /></div>
      </MutationForm>}
    </section>}
  </main>;
}
