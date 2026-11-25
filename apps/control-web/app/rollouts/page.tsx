import { randomUUID } from 'node:crypto';
import { redirect } from 'next/navigation';
import type { ControlSession } from '../../lib/access';
import { canWrite } from '../../lib/access';
import { ApiError, controlApi } from '../../lib/api';
import { aiPromptApps, promptAppLabels, utc, type Policy, type PolicyGroup } from '../../lib/control';
import { maxRolloutStages, percent, rolloutPauseReasons, rolloutStageStates, rolloutStatuses, soakLabel,
  type RolloutGate, type RolloutPlan, type RolloutStage } from '../../lib/rollouts';
import { sessionToken } from '../../lib/session';
import { changeRolloutPlan, createRolloutPlan } from '../actions';
import { MutationForm, RefreshSection } from '../forms';
import { DeploymentBadge, Sidebar } from '../workspace';

type Search = { plan?: string | string[]; source?: string | string[] };

export default async function Rollouts({ searchParams }: { searchParams: Promise<Search> }) {
  const token = await sessionToken();
  if (!token) redirect('/');
  const { plan: selectedId, source } = await searchParams;
  const result = await load(token).catch((error) => {
    if (error instanceof ApiError && error.status === 401) redirect('/');
    if (error instanceof ApiError) return undefined;
    throw error;
  });
  const selected = result && (selectedId === undefined ? result.plans[0] : result.plans.find((plan) => plan.id === selectedId));
  const canCreate = canWrite(result?.session) && (!result?.session.reviewRequired || result.session.role === 'administrator');
  return <div className="workspace">
    <Sidebar active="rollouts" session={result?.session} />
    <main className="dashboard">
      <header className="page-heading">
        <div>{result && <p className="eyebrow">{result.session.organization}</p>}<h1>Automated rollouts</h1></div>
        <DeploymentBadge />
      </header>
      {result ? <>
        <section className="panel" aria-labelledby="plans-heading">
          <div className="panel-heading"><h2 id="plans-heading">Rollout plans</h2><RefreshSection label="Refresh rollout plans" /></div>
          <p className="muted">A plan publishes one reviewed policy version to each stage in order. After the soak time, Control checks the
            stage's browsers and advances only when every gate passes. Block and override limits halt a stage at any time.</p>
          {result.plans.length ? <nav className="form-row" aria-label="Rollout plans">
            {result.plans.map((plan) => <a key={plan.id} href={`/rollouts?plan=${plan.id}`}
              className={`button small ${selected?.id === plan.id ? 'primary' : ''}`} aria-current={selected?.id === plan.id ? 'page' : undefined}>
              {plan.name} · {rolloutStatuses[plan.status]}</a>)}
          </nav> : <p className="muted">No rollout plans yet.</p>}
        </section>
        {selectedId !== undefined && !selected &&
          <section className="panel" role="alert">This rollout plan is unavailable. Choose a plan from the list.</section>}
        {selected && <PlanDetails plan={selected} session={result.session} />}
        {canCreate ? <CreatePlan groups={result.groups} versions={result.versions} source={typeof source === 'string' ? source : undefined} />
          : canWrite(result.session) && <section className="panel"><p className="muted">Sign in as a named administrator to plan a rollout while
            policy reviews are required.</p></section>}
      </> : <section className="panel" role="alert">Control could not load rollout plans. Reload to try again.</section>}
    </main>
  </div>;
}

async function load(token: string) {
  const [session, plans, groups, baseline] = await Promise.all([
    controlApi.session(token), controlApi.rolloutPlans(token), controlApi.groups(token), controlApi.policies(token),
  ]);
  const histories = await Promise.all(groups.map((group) => controlApi.policies(token, group.id)));
  const versions: { label: string; policies: Policy[] }[] = [{ label: 'Organization baseline', policies: baseline.slice(0, 20) },
    ...groups.map((group, index) => ({ label: group.name, policies: histories[index].slice(0, 20) }))].filter(({ policies }) => policies.length);
  return { session, plans, groups, versions };
}

function PlanDetails({ plan, session }: { plan: RolloutPlan; session: ControlSession }) {
  const writable = canWrite(session);
  const named = session.role === 'administrator' && session.access;
  const policyAction = writable && (!session.reviewRequired || named);
  const own = session.access?.id === plan.creator?.id;
  const action = (operation: string, label: string, confirmation: string, appearance = '') =>
    <MutationForm key={operation} action={changeRolloutPlan} label={label} appearance={appearance} confirmation={confirmation}>
      <input type="hidden" name="id" value={plan.id} />
      <input type="hidden" name="operation" value={operation} />
    </MutationForm>;
  const current = plan.stages[plan.currentStage];
  return <section className="panel" aria-labelledby="plan-heading">
    <div className="panel-heading">
      <h2 id="plan-heading">{plan.name}</h2>
      <span className={`badge ${plan.status === 'running' || plan.status === 'completed' ? 'current' : plan.status === 'paused' ? 'warn' : ''}`}>
        {rolloutStatuses[plan.status]}</span>
    </div>
    <p className="muted">Policy v{plan.sourceVersion} · Requested by {plan.creator?.name ?? 'Organization admin'} · {utc.format(new Date(plan.createdAt))} UTC
      {plan.approver && plan.requiresReview && <> · Approved by {plan.approver.name}</>}</p>
    {plan.status === 'paused' && plan.pauseReason && <p className="feedback error" role="alert">
      Paused at stage {plan.currentStage + 1}: {rolloutPauseReasons[plan.pauseReason]}</p>}
    {plan.status === 'running' && current && <p role="status">Stage {plan.currentStage + 1} of {plan.stages.length} · {scope(current)}
      {plan.nextEvaluationAt && <> · Next evaluation {utc.format(new Date(plan.nextEvaluationAt))} UTC</>}</p>}
    {plan.status === 'pending_review' && <p className="muted">Waiting for a different named administrator. Expires {utc.format(new Date(plan.expiresAt))} UTC.</p>}
    {plan.gate && <GateTable gate={plan.gate} stage={plan.stages[plan.gate.stage]} />}
    <div className="table-scroll" tabIndex={0} role="region" aria-labelledby="stages-heading">
      <h3 id="stages-heading" className="mt-3">Stages</h3>
      <table aria-labelledby="stages-heading">
        <thead><tr><th>Stage</th><th>Target</th><th>Gates</th><th>Policy</th><th>Status</th></tr></thead>
        <tbody>{plan.stages.map((stage) => <tr key={stage.position}>
          <td>{stage.position + 1}</td>
          <td>{scope(stage)}</td>
          <td>{gateSummary(stage)}</td>
          <td>{stage.publishedVersion ? <>v{stage.publishedVersion} · from v{stage.priorVersion}
            {stage.rollbackVersion && <> · restored as v{stage.rollbackVersion}</>}</> : '—'}</td>
          <td>{rolloutStageStates[stage.state]}</td>
        </tr>)}</tbody>
      </table>
    </div>
    <div className="form-row mt-3">
      {plan.status === 'pending_review' && named && !own && action('approve', 'Approve and start', `Start ${plan.name} and publish stage 1?`, 'primary')}
      {plan.status === 'pending_review' && named && action('reject', own ? 'Withdraw plan' : 'Reject plan', `Close ${plan.name}?`)}
      {plan.status === 'running' && writable && action('pause', 'Pause rollout', `Pause ${plan.name}?`)}
      {plan.status === 'paused' && policyAction && action('resume', 'Resume rollout', `Resume ${plan.name} and evaluate the current stage now?`, 'primary')}
      {['running', 'paused', 'completed'].includes(plan.status) && policyAction &&
        action('rollback', 'Roll back plan', `Restore the prior policy in every scope this plan changed?`, 'danger')}
      {['running', 'paused'].includes(plan.status) && writable &&
        action('cancel', 'Stop without rollback', `Stop ${plan.name}? Published stages keep their policy.`)}
    </div>
  </section>;
}

function GateTable({ gate, stage }: { gate: RolloutGate; stage?: RolloutStage }) {
  const row = (name: string, actual: string, threshold: string, passed: boolean) =>
    <tr key={name}><td>{name}</td><td>{actual}</td><td>{threshold}</td><td>{passed ? 'Pass' : 'Fail'}</td></tr>;
  const { acknowledgment: ack, blocks, overrides } = gate;
  return <div className="table-scroll" tabIndex={0} role="region" aria-labelledby="gate-heading">
    <h3 id="gate-heading" className="mt-3">Stage {gate.stage + 1} gates · v{gate.policyVersion}</h3>
    <p className="muted">Evaluated {utc.format(new Date(gate.evaluatedAt))} UTC · {gate.soaked ? 'Soak complete' :
      `Soaking until ${utc.format(new Date(gate.soakEndsAt))} UTC`}{stage && ` · ${scope(stage)}`}</p>
    <table aria-labelledby="gate-heading">
      <thead><tr><th>Gate</th><th>Actual</th><th>Threshold</th><th>Result</th></tr></thead>
      <tbody>
        {row('Policy acknowledged', `${ack.acknowledged} of ${ack.active} browsers (${percent(ack.acknowledged, ack.active)}%)`,
          `At least ${ack.threshold}%`, ack.passed)}
        {gate.composers.map((composer) => row(`${promptAppLabels[composer.appId]} composer`,
          `${composer.detected} of ${composer.active} detected · ${composer.unsupported} unsupported`, 'All detected', composer.passed))}
        {row('Block events', String(blocks.blocks), blocks.threshold === null ? 'No limit' : `At most ${blocks.threshold}`, blocks.passed)}
        {row('Warning overrides', `${overrides.overrides} of ${overrides.warnings} warnings (${percent(overrides.overrides, Math.max(overrides.warnings, overrides.overrides))}%)`,
          overrides.threshold === null ? 'No limit' : `At most ${overrides.threshold}%`, overrides.passed)}
        {gate.currentVersion !== gate.policyVersion && row('Stage policy unchanged', `v${gate.currentVersion}`, `v${gate.policyVersion}`, false)}
      </tbody>
    </table>
  </div>;
}

function scope(stage: RolloutStage) {
  return stage.groupName ?? (stage.groupId ? 'Unavailable group' : 'Organization baseline');
}

function gateSummary(stage: RolloutStage) {
  return [soakLabel(stage.minSoakSeconds), `≥${stage.minAcknowledgedPercent}% acknowledged`,
    ...stage.requireComposerReady.map((app) => `${promptAppLabels[app]} ready`),
    stage.maxBlockEvents !== null && `≤${stage.maxBlockEvents} blocks`,
    stage.maxWarnOverridePercent !== null && `≤${stage.maxWarnOverridePercent}% overrides`].filter(Boolean).join(' · ');
}

function CreatePlan({ groups, versions, source }: { groups: PolicyGroup[]; versions: { label: string; policies: Policy[] }[]; source?: string }) {
  return <section className="panel" aria-labelledby="create-plan-heading">
    <h2 id="create-plan-heading">Plan a rollout</h2>
    <p className="muted">Leave unused stages empty. Put the organization baseline last; it also reaches groups that follow the baseline.
      When policy reviews are required, another named administrator approves the plan before stage 1 publishes.</p>
    <MutationForm action={createRolloutPlan} label="Create rollout plan" appearance="primary" preserveValues>
      <input type="hidden" name="requestId" value={randomUUID()} />
      <div className="policy-fields">
        <div className="grid gap-1">
          <label htmlFor="rollout-name">Plan name</label>
          <input id="rollout-name" name="name" required minLength={2} maxLength={64} />
        </div>
        <div className="grid gap-1">
          <label htmlFor="rollout-source">Policy version to roll out</label>
          <select id="rollout-source" name="sourceVersion" required defaultValue={source ?? ''}>
            <option value="" disabled>Choose a published version</option>
            {versions.map(({ label, policies }) => <optgroup key={label} label={label}>
              {policies.map((policy) => <option key={policy.version} value={policy.version}>v{policy.version} · {policy.mode}</option>)}
            </optgroup>)}
          </select>
        </div>
      </div>
      {Array.from({ length: maxRolloutStages }, (_, index) => <fieldset key={index} className="policy-fields rollout-stage">
        <legend>Stage {index + 1}</legend>
        <div className="grid gap-1">
          <label htmlFor={`stage${index}-target`}>Target</label>
          <select id={`stage${index}-target`} name={`stage${index}Target`} defaultValue="">
            <option value="">Not used</option>
            {groups.map((group) => <option key={group.id} value={group.id}>{group.name}</option>)}
            <option value="baseline">Organization baseline</option>
          </select>
        </div>
        <div className="grid gap-1">
          <label htmlFor={`stage${index}-soak`}>Soak minutes</label>
          <input id={`stage${index}-soak`} name={`stage${index}Soak`} type="number" min={0} max={10080} defaultValue={60} required />
        </div>
        <div className="grid gap-1">
          <label htmlFor={`stage${index}-ack`}>Minimum acknowledged %</label>
          <input id={`stage${index}-ack`} name={`stage${index}Ack`} type="number" min={0} max={100} defaultValue={90} required />
        </div>
        <div className="grid gap-1">
          <label htmlFor={`stage${index}-blocks`}>Halt after block events</label>
          <input id={`stage${index}-blocks`} name={`stage${index}Blocks`} type="number" min={0} max={100000} placeholder="No limit" />
        </div>
        <div className="grid gap-1">
          <label htmlFor={`stage${index}-overrides`}>Halt above override %</label>
          <input id={`stage${index}-overrides`} name={`stage${index}Overrides`} type="number" min={0} max={100} placeholder="No limit" />
        </div>
        <div role="group" aria-label={`Stage ${index + 1} required composer checks`} className="form-row">
          {aiPromptApps.map((app) => <label key={app} className="form-row">
            <input type="checkbox" name={`stage${index}App`} value={app} /> {promptAppLabels[app]}</label>)}
        </div>
      </fieldset>)}
    </MutationForm>
  </section>;
}
