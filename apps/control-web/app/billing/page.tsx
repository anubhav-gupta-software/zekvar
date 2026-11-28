import { randomUUID } from 'node:crypto';
import { redirect } from 'next/navigation';
import { ApiError, controlApi } from '../../lib/api';
import { canSeeBilling, lastDay, meteringRuleText, money, paymentLabels, percent, providerLabels, termLabels, 
  type BillingOverview } from '../../lib/billing';
import { utc } from '../../lib/control';
import { sessionToken } from '../../lib/session';
import { acceptBillingQuote, createBillingQuote, withdrawBillingQuote } from '../actions';
import { MutationForm, RefreshSection } from '../forms';
import { DeploymentBadge, Sidebar } from '../workspace';
import { Lines, Totals } from './lines';

export default async function BillingPage({ searchParams }: { searchParams: Promise<{ accepted?: string; effectiveOn?: string }> }) {
  const { accepted, effectiveOn } = await searchParams;
  const token = await sessionToken();
  if (!token) redirect('/');
  const data = await load(token).catch((error) => {
    if (error instanceof ApiError && error.status === 401) redirect('/');
    if (error instanceof ApiError) return undefined;
    throw error;
  });
  const session = data?.session;
  const billing = data?.billing;
  const owner = session?.role === 'owner';
  return <div className="workspace">
    <Sidebar active="billing" session={session} />
    <main className="dashboard">
      <header className="page-heading">
        <div>{session && <p className="eyebrow">{session.organization}</p>}<h1>Billing</h1></div>
        <DeploymentBadge />
      </header>
      {!data ? <section className="panel" role="alert">Control could not load billing. Try reloading this page.</section>
        : !canSeeBilling(session) ? <section className="panel" role="alert">Only the organization owner and auditors can view billing.</section>
        : !billing ? <section className="panel" role="status">Billing is not configured for this Control deployment.</section>
        : <>
          {accepted === '1' && <p className="feedback" role="status">Quote accepted.{typeof effectiveOn === 'string' &&
            /^\d{4}-\d{2}-\d{2}$/.test(effectiveOn) ? ` The new commitment starts on ${effectiveOn}.` : ''}</p>}
          <BillingView billing={billing} owner={owner} />
        </>}
    </main>
  </div>;
}

async function load(token: string) {
  const session = await controlApi.session(token);
  if (!canSeeBilling(session)) return { session };
  const billing = await controlApi.billing(token).catch((error: unknown) => {
    if (error instanceof ApiError && error.status === 404) return undefined;
    throw error;
  });
  return { session, billing };
}

function BillingView({ billing, owner }: { billing: BillingOverview; owner: boolean }) {
  const format = (amount: number) => money(amount, billing.currency, billing.minorUnitDigits);
  const { subscription, estimate, currentUsage } = billing;
  const peak = Math.max(1, ...billing.usage.map(({ activeSeats }) => activeSeats));
  return <>
    {billing.taxPlaceholder && <p className="panel muted" role="note">
      Prices, tax rate ({billing.taxLabel}, {percent(billing.taxBasisPoints)}), and the metering rule come from operator configuration
      (price book {billing.priceBookVersion}). They are placeholders until confirmed.
    </p>}
    <div className="metrics">
      <div className="metric"><p>Plan</p><strong>{subscription ? `${subscription.committedSeats} seats` : 'No subscription'}</strong>
        <span>{subscription ? `${subscription.planName} · ${termLabels[subscription.term]}` : 'Create and accept a quote to start'}</span></div>
      <div className="metric"><p>Peak active seats</p><strong>{currentUsage?.peakSeats ?? 0}</strong>
        <span>{currentUsage ? `${currentUsage.periodStart} to ${lastDay(currentUsage.periodEnd)}` : '—'}</span></div>
      <div className="metric"><p>Upcoming invoice</p><strong>{estimate ? format(estimate.total) : '—'}</strong>
        <span>{estimate ? `Estimate, issued ${estimate.issueOn}` : 'No subscription'}</span></div>
    </div>

    <section className="panel" aria-labelledby="subscription-heading">
      <h2 id="subscription-heading">Subscription</h2>
      {subscription ? <dl className="billing-facts">
        <div><dt>Customer</dt><dd>{subscription.customerName}</dd></div>
        <div><dt>Started</dt><dd>{subscription.startedOn}</dd></div>
        <div><dt>Commitment period</dt><dd>{subscription.commitmentPeriodStart} to {lastDay(subscription.commitmentPeriodEnd)}</dd></div>
        <div><dt>Usage period</dt><dd>{subscription.currentPeriodStart} to {lastDay(subscription.currentPeriodEnd)}</dd></div>
        <div><dt>Payment</dt><dd>{billing.provider === 'stripe' ? 'Card or invoice through the payment provider' : 'Bank transfer'}</dd></div>
        {subscription.pendingChange && <div><dt>Scheduled change</dt>
          <dd>{subscription.pendingChange.committedSeats} seats from {subscription.pendingChange.effectiveOn}</dd></div>}
      </dl> : <p className="muted">This organization has no subscription.</p>}
      <p className="muted billing-rule">{meteringRuleText} Seats above the commitment are billed as overage at the end of each usage period.
        Increases take effect immediately with a daily proration; decreases start with the next commitment period.</p>
    </section>

    {estimate && <section className="panel table-panel" aria-labelledby="estimate-heading">
      <div className="panel-heading"><h2 id="estimate-heading">Upcoming invoice estimate</h2><RefreshSection label="Refresh billing" /></div>
      <Lines lines={estimate.lines} format={format} label="estimate-heading" />
      <Totals subtotal={estimate.subtotal} tax={estimate.taxAmount} total={estimate.total} taxLabel={`${billing.taxLabel} (${percent(estimate.taxBasisPoints)})`}
        format={format} />
    </section>}

    {owner && <section className="panel" aria-labelledby="quote-heading">
      <h2 id="quote-heading">{subscription ? 'Quote a seat change' : 'Create a quote'}</h2>
      <p className="muted">A quote fixes the price book prices for {subscription ? 'the change' : 'the subscription'}. Accepting it
        {subscription ? ' changes the commitment.' : ' starts the subscription and issues the first invoice.'}</p>
      <MutationForm action={createBillingQuote} label="Create quote" appearance="primary">
        <input type="hidden" name="requestId" value={randomUUID()} />
        <div className="grid gap-1"><label htmlFor="quote-plan">Plan</label>
          <select id="quote-plan" name="planId">{billing.plans.map((plan) => <option key={plan.id} value={plan.id}>{plan.name}</option>)}</select></div>
        <div className="grid gap-1"><label htmlFor="quote-term">Term</label>
          <select id="quote-term" name="term" defaultValue={subscription?.term ?? 'monthly'}>
            <option value="monthly">Monthly</option><option value="annual">Annual</option></select></div>
        <div className="grid gap-1"><label htmlFor="quote-seats">Committed seats</label>
          <input id="quote-seats" name="committedSeats" type="number" min={1} max={1000000} required
            defaultValue={subscription?.committedSeats ?? Math.max(1, currentUsage?.peakSeats ?? 1)} /></div>
        <div className="grid gap-1"><label htmlFor="quote-customer">Customer name</label>
          <input id="quote-customer" name="customerName" required minLength={2} maxLength={120} defaultValue={subscription?.customerName} /></div>
        <div className="grid gap-1"><label htmlFor="quote-email">Billing email</label>
          <input id="quote-email" name="billingEmail" type="email" required maxLength={254} /></div>
      </MutationForm>
    </section>}

    <section className="panel table-panel" aria-labelledby="quotes-heading">
      <div className="panel-heading"><h2 id="quotes-heading">Quotes</h2></div>
      {billing.quotes.length ? <div className="table-scroll" role="region" tabIndex={0} aria-labelledby="quotes-heading">
        <table aria-labelledby="quotes-heading">
          <thead><tr><th>Created (UTC)</th><th>Plan</th><th>Seats</th><th>Term</th><th>Total per period</th><th>Status</th><th>Action</th></tr></thead>
          <tbody>{billing.quotes.map((quote) => <tr key={quote.id}>
            <td><time dateTime={quote.createdAt}>{utc.format(new Date(quote.createdAt))}</time></td>
            <th scope="row" className="emphasis">{quote.planName}{quote.amendment && <div className="muted">Change to subscription</div>}</th>
            <td>{quote.committedSeats}</td><td>{termLabels[quote.term]}</td>
            <td>{money(quote.total, quote.currency, quote.minorUnitDigits)}</td>
            <td><span className={`badge ${quote.status === 'accepted' ? 'current' : ''}`}>{quote.status[0].toUpperCase() + quote.status.slice(1)}</span></td>
            <td>{owner && quote.status === 'open' ? <div className="form-row">
              <MutationForm action={acceptBillingQuote} label="Accept" appearance="small primary"
                accessibleLabel={`Accept quote for ${quote.committedSeats} seats`}
                confirmation={`Accept this quote for ${quote.committedSeats} seats at ${money(quote.total, quote.currency, quote.minorUnitDigits)} per ${quote.term === 'annual' ? 'year' : 'month'}?`}>
                <input type="hidden" name="id" value={quote.id} />
              </MutationForm>
              <MutationForm action={withdrawBillingQuote} label="Withdraw" appearance="small" accessibleLabel={`Withdraw quote for ${quote.committedSeats} seats`}>
                <input type="hidden" name="id" value={quote.id} />
              </MutationForm>
            </div> : '—'}</td>
          </tr>)}</tbody>
        </table>
      </div> : <p className="empty">No quotes yet.</p>}
    </section>

    <section className="panel table-panel" aria-labelledby="invoices-heading">
      <div className="panel-heading"><h2 id="invoices-heading">Invoices and credit notes</h2></div>
      {billing.invoices.length ? <div className="table-scroll" role="region" tabIndex={0} aria-labelledby="invoices-heading">
        <table aria-labelledby="invoices-heading">
          <thead><tr><th>Number</th><th>Issued (UTC)</th><th>Period</th><th>Total</th><th>Status</th><th>Documents</th></tr></thead>
          <tbody>{billing.invoices.map((invoice) => <tr key={invoice.id}>
            <th scope="row" className="emphasis">{invoice.number}<div className="muted">{invoice.kind === 'credit_note' ? 'Credit note' : 'Invoice'}</div></th>
            <td><time dateTime={invoice.issuedAt}>{utc.format(new Date(invoice.issuedAt))}</time></td>
            <td>{invoice.periodStart && invoice.periodEnd ? `${invoice.periodStart} to ${lastDay(invoice.periodEnd)}` : '—'}</td>
            <td>{money(invoice.total, invoice.currency, invoice.minorUnitDigits)}</td>
            <td><span className={`badge ${invoice.paymentStatus === 'paid' ? 'current' : ''}`}>{paymentLabels[invoice.paymentStatus]}</span>
              {invoice.kind === 'invoice' && <div className="muted">{providerLabels[invoice.providerStatus]}</div>}</td>
            <td><div className="form-row">
              <a className="button small" href={`/billing/invoices/${invoice.id}`} aria-label={`View ${invoice.number}`}>View</a>
              <a className="button small" href={`/billing/invoices/${invoice.id}/export`} download aria-label={`Download ${invoice.number} JSON`}>JSON</a>
            </div></td>
          </tr>)}</tbody>
        </table>
      </div> : <p className="empty">No invoices have been issued.</p>}
    </section>

    <section className="panel table-panel" aria-labelledby="usage-heading">
      <div className="panel-heading"><h2 id="usage-heading">Daily active seats</h2></div>
      <p className="empty">Last 35 UTC days. Days are frozen after they end; today is provisional.</p>
      <div className="table-scroll" role="region" tabIndex={0} aria-labelledby="usage-heading">
        <table aria-labelledby="usage-heading" className="report-table">
          <thead><tr><th>Day (UTC)</th><th>Active seats</th><th>Enrolled browsers</th></tr></thead>
          <tbody>{[...billing.usage].reverse().map((day) => <tr key={day.date}>
            <th scope="row">{day.date}{day.provisional && <span className="muted"> · provisional</span>}</th>
            <td><span className="report-total">{day.activeSeats}<meter min={0} max={peak} value={day.activeSeats} aria-hidden="true" /></span></td>
            <td>{day.enrolledSeats}</td>
          </tr>)}</tbody>
        </table>
      </div>
    </section>
  </>;
}
