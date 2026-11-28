import type { ControlSession } from './access';

export type BillingTerm = 'monthly' | 'annual';
export type BillingTier = { upTo: number | null; monthlyUnitAmount: number; annualUnitAmount: number };
export type BillingLine = {
  kind: 'commitment' | 'overage' | 'proration_credit' | 'proration_charge' | 'credit';
  description: string; quantity: number; unitAmount: number; numerator: number; denominator: number; amount: number;
};
export type BillingUsagePeriod = {
  periodStart: string; periodEnd: string; peakSeats: number; peakDate: string | null; committedSeats: number; overageSeats: number;
  daysMeasured: number; rule: string;
};
export type BillingQuote = {
  id: string; status: 'open' | 'accepted' | 'withdrawn' | 'expired'; planId: string; planName: string; term: BillingTerm; committedSeats: number;
  currency: string; minorUnitDigits: number; lines: BillingLine[]; subtotal: number; taxBasisPoints: number; taxLabel: string; taxAmount: number;
  total: number; customerName: string; amendment: boolean; createdAt: string; expiresAt: string;
};
export type BillingSubscription = {
  id: string; revision: number; startedOn: string; planName: string; term: BillingTerm; committedSeats: number; currency: string; customerName: string;
  currentPeriodStart: string; currentPeriodEnd: string; commitmentPeriodStart: string; commitmentPeriodEnd: string;
  pendingChange: { quoteId: string; planName: string; committedSeats: number; effectiveOn: string } | null;
};
export type BillingInvoiceSummary = {
  id: string; kind: 'invoice' | 'credit_note'; number: string; reason: string; issuedAt: string; periodStart: string | null; periodEnd: string | null;
  currency: string; minorUnitDigits: number; total: number; creditedTotal: number; paymentStatus: 'open' | 'paid' | 'credited' | 'issued';
  providerStatus: 'not_applicable' | 'pending' | 'submitted' | 'failed'; relatedInvoiceId: string | null;
};
export type BillingInvoice = Omit<BillingInvoiceSummary, 'relatedInvoiceId'> & {
  relatedInvoiceId: string | null; relatedNumber: string | null; dueOn: string | null; lines: BillingLine[]; usage: BillingUsagePeriod | null;
  subtotal: number; taxBasisPoints: number; taxLabel: string; taxAmount: number; balanceDue: number; issuer: { name: string; detail: string };
  customer: { name: string; detail: string }; planName: string; term: BillingTerm; note: string | null; provider: 'manual' | 'stripe';
  paidAt: string | null; paymentReference: string | null; paymentInstructions: string | null; creditNotes: BillingInvoiceSummary[];
};
export type BillingOverview = {
  organization: string; provider: 'manual' | 'stripe'; currency: string; minorUnitDigits: number; tierMode: 'volume' | 'graduated';
  taxBasisPoints: number; taxLabel: string; taxPlaceholder: boolean; meteringRule: string; priceBookVersion: string;
  plans: { id: string; name: string; tiers: BillingTier[] }[];
  subscription: BillingSubscription | null; currentUsage: BillingUsagePeriod | null;
  estimate: { issueOn: string; lines: BillingLine[]; subtotal: number; taxBasisPoints: number; taxAmount: number; total: number } | null;
  usage: { date: string; activeSeats: number; enrolledSeats: number; provisional: boolean }[];
  quotes: BillingQuote[]; invoices: BillingInvoiceSummary[];
};

export const canSeeBilling = (session?: ControlSession) => session?.role === 'owner' || session?.role === 'auditor';

// Formats integer minor units exactly, without floating-point conversion.
export function money(amount: number, currency: string, digits: number) {
  const negative = amount < 0;
  const text = String(Math.abs(Math.trunc(amount))).padStart(digits + 1, '0');
  const whole = text.slice(0, text.length - digits).replace(/\B(?=(\d{3})+(?!\d))/g, ',');
  const fraction = digits > 0 ? `.${text.slice(text.length - digits)}` : '';
  return `${negative ? '−' : ''}${currency} ${whole}${fraction}`;
}

export const percent = (basisPoints: number) => `${(basisPoints / 100).toFixed(2).replace(/\.?0+$/, '')}%`;
export const lastDay = (exclusiveEnd: string) => new Date(Date.parse(`${exclusiveEnd}T00:00:00Z`) - 86_400_000).toISOString().slice(0, 10);

export const termLabels: Record<BillingTerm, string> = { monthly: 'Monthly', annual: 'Annual' };
export const paymentLabels: Record<BillingInvoiceSummary['paymentStatus'], string> = {
  open: 'Awaiting payment', paid: 'Paid', credited: 'Fully credited', issued: 'Issued',
};
export const providerLabels: Record<BillingInvoiceSummary['providerStatus'], string> = {
  not_applicable: 'Bank transfer', pending: 'Sending to provider', submitted: 'Sent to provider', failed: 'Provider rejected',
};
export const meteringRuleText = 'A browser counts as an active seat on a UTC day when it is enrolled and not revoked at the end of that day and ' +
  'checked in with Control that day or in the six days before. Billable seats for a monthly usage period are the highest daily count.';
