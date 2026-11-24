import { redirect } from 'next/navigation';
import { canChangePolicy, canWrite, type ControlSession } from '../../lib/access';
import { ApiError, controlApi } from '../../lib/api';
import { isId, type Policy, type PolicyGroup } from '../../lib/control';
import { previewSnapshot, samePolicy } from '../../lib/preview';
import { sessionToken } from '../../lib/session';
import type { PolicyTemplate, PolicyTemplateDetails, PolicyTemplatePreview } from '../../lib/templates';
import { applyPolicyTemplate, archivePolicyTemplate, createPolicyTemplate, revisePolicyTemplate } from '../actions';
import { MutationForm, RefreshSection } from '../forms';
import { PolicyChanges } from '../policy-changes';
import { DeploymentBadge, Sidebar } from '../workspace';

type Search = Record<string, string | string[] | undefined>;
type TemplateView = {
  session: ControlSession; templates: PolicyTemplate[]; groups: PolicyGroup[]; sourceGroup?: string; sourcePolicies: Policy[];
  targetGroup?: string; revision?: number; details?: PolicyTemplateDetails; comparison?: PolicyTemplatePreview; error?: string;
};

export default async function Templates({ searchParams }: { searchParams: Promise<Search> }) {
  const token = await sessionToken();
  if (!token) redirect('/');
  const search = await searchParams;
  const data = await loadTemplates(token, search).catch((error) => {
    if (error instanceof ApiError && error.status === 401) redirect('/');
    if (error instanceof ApiError) return undefined;
    throw error;
  });
  const selected = data?.details?.template;
  return <div className="workspace">
    <Sidebar active="templates" session={data?.session} />
    <main className="dashboard">
      <header className="page-heading">
        <div>{data && <p className="eyebrow">{data.session.organization}</p>}<h1>Policy templates</h1></div>
        <DeploymentBadge />
      </header>
      {data ? <>
        <section className="panel" aria-labelledby="template-library-heading">
          <div className="panel-heading"><h2 id="template-library-heading">Template library</h2><RefreshSection label="Refresh policy templates" /></div>
          {data.templates.length ? <nav className="form-row group-menu" aria-label="Saved templates">
            {data.templates.map(({ id, name, revision }) => <a key={id} className={`button small ${id === selected?.id ? 'primary' : ''}`}
              aria-current={id === selected?.id ? 'page' : undefined} href={`/templates?template=${id}`}>
              {name}<span className="group-count">Revision {revision}</span>
            </a>)}
            {selected && canWrite(data.session) && <a className="button small" href="/templates">New template</a>}
          </nav> : <p className="muted">No active templates. Save a published policy to create one.</p>}
        </section>
        {data.error && <section className="panel" role="alert">{data.error}</section>}
        {data.details && <CompareTemplate data={data} details={data.details} />}
        {canWrite(data.session) && <SaveTemplate data={data} selected={selected} />}
      </> : <section className="panel" role="alert">Control could not load the policy template library.</section>}
    </main>
  </div>;
}

function CompareTemplate({ data, details }: { data: TemplateView; details: PolicyTemplateDetails }) {
  const { template, revisions } = details;
  const result = data.comparison;
  const scope = result?.groupName ?? 'Organization baseline';
  const before = result && previewSnapshot(result.before, scope);
  const candidate = result && previewSnapshot(result.candidate, result.template.name);
  const review = data.session.reviewRequired;
  return <section className="panel" aria-labelledby="compare-template-heading">
    <h2 id="compare-template-heading">Compare {template.name}</h2>
    <form action="/templates" method="get" className="form-row">
      <input type="hidden" name="template" value={template.id} />
      {data.sourceGroup && <input type="hidden" name="sourceGroup" value={data.sourceGroup} />}
      <div className="grid gap-1">
        <label htmlFor="template-revision">Template revision</label>
        <select id="template-revision" name="revision" defaultValue={data.revision ?? template.revision}>
          {revisions.map(({ revision, sourceVersion }) => <option key={revision} value={revision}>Revision {revision} · Policy v{sourceVersion}</option>)}
        </select>
      </div>
      <GroupSelect name="targetGroup" label="Destination policy" selected={data.targetGroup} groups={data.groups} />
      <button className="button">Compare settings</button>
    </form>
    {result && before && candidate && <div className="mt-3">
      <p className="muted">Template revision {result.template.revision} from policy v{result.template.sourceVersion} · {scope} v{before.version}.</p>
      {samePolicy(before, candidate) ? <p className="muted">The template settings match the destination policy.</p>
        : <PolicyChanges reference={before} candidate={candidate} />}
      {canChangePolicy(data.session) && <MutationForm action={applyPolicyTemplate}
        label={review ? 'Request template review' : 'Apply template'} appearance="primary"
        confirmation={`Use revision ${result.template.revision} of ${template.name} for ${scope}?`}>
        <input type="hidden" name="templateId" value={template.id} />
        <input type="hidden" name="revision" value={result.template.revision} />
        <input type="hidden" name="expectedVersion" value={before.version} />
        {data.targetGroup && <input type="hidden" name="targetGroup" value={data.targetGroup} />}
        {review && <input type="hidden" name="expectReview" value="on" />}
      </MutationForm>}
    </div>}
  </section>;
}

function SaveTemplate({ data, selected }: { data: TemplateView; selected?: PolicyTemplate }) {
  return <section className="panel" aria-labelledby="save-template-heading">
    <h2 id="save-template-heading">{selected ? `Manage ${selected.name}` : 'Save a policy template'}</h2>
    <p className="muted">Choose a published policy to pin as a reusable revision. Temporary prompt exceptions stay with the destination.</p>
    <form action="/templates" method="get" className="form-row">
      {selected && <input type="hidden" name="template" value={selected.id} />}
      {data.revision && <input type="hidden" name="revision" value={data.revision} />}
      {data.targetGroup && <input type="hidden" name="targetGroup" value={data.targetGroup} />}
      <GroupSelect name="sourceGroup" label="Source scope" selected={data.sourceGroup} groups={data.groups} />
      <button className="button">Load source policies</button>
    </form>
    {data.sourcePolicies.length ? <MutationForm action={selected ? revisePolicyTemplate : createPolicyTemplate}
      label={selected ? 'Save template revision' : 'Create template'} appearance="primary">
      {selected ? <>
        <input type="hidden" name="templateId" value={selected.id} />
        <input type="hidden" name="expectedRevision" value={selected.revision} />
      </> : <div className="grid gap-1">
        <label htmlFor="template-name">Template name</label>
        <input id="template-name" name="name" minLength={2} maxLength={64} required />
      </div>}
      <div className="grid gap-1">
        <label htmlFor="template-source-version">Source policy version</label>
        <select id="template-source-version" name="sourceVersion" key={data.sourceGroup ?? 'baseline'}>
          {data.sourcePolicies.map(({ version }) => <option key={version} value={version}>v{version}</option>)}
        </select>
      </div>
    </MutationForm> : <p className="muted">Publish a policy in this source scope to save it as a template.</p>}
    {selected && <div className="mt-3">
      <MutationForm action={archivePolicyTemplate} label="Archive template" appearance="small danger"
        confirmation={`Archive ${selected.name}? Pending applications of this template will become stale.`}>
        <input type="hidden" name="templateId" value={selected.id} />
        <input type="hidden" name="expectedRevision" value={selected.revision} />
      </MutationForm>
    </div>}
  </section>;
}

function GroupSelect({ name, label, selected, groups }: { name: string; label: string; selected?: string; groups: PolicyGroup[] }) {
  return <div className="grid gap-1">
    <label htmlFor={`template-${name}`}>{label}</label>
    <select id={`template-${name}`} name={name} defaultValue={selected ?? ''}>
      <option value="">Organization baseline</option>
      {groups.map(({ id, name }) => <option key={id} value={id}>{name}</option>)}
    </select>
  </div>;
}

async function loadTemplates(token: string, search: Search): Promise<TemplateView> {
  const [session, templates, groups] = await Promise.all([controlApi.session(token), controlApi.templates(token), controlApi.groups(token)]);
  const result: TemplateView = { session, templates, groups, sourcePolicies: [] };
  const { template, revision, sourceGroup, targetGroup } = search;
  const group = (value: string | string[] | undefined) => isId(value) ? groups.find(({ id }) => id === value.toLowerCase())?.id : undefined;
  result.sourceGroup = group(sourceGroup);
  result.targetGroup = group(targetGroup);
  if ((sourceGroup && !result.sourceGroup) || (targetGroup && !result.targetGroup)) {
    return { ...result, error: 'This policy scope is unavailable. Choose another group from the template library.' };
  }
  if (canWrite(session)) result.sourcePolicies = await controlApi.policies(token, result.sourceGroup);
  if (!template && !revision && !targetGroup) return result;
  const selected = isId(template) ? templates.find(({ id }) => id === template.toLowerCase()) : undefined;
  if (!selected) return { ...result, error: 'This template is unavailable. Choose an active template.' };
  try {
    result.details = await controlApi.template(token, selected.id);
    if (revision === undefined || revision === '') return result;
    if (typeof revision !== 'string' || !/^[1-9]\d{0,9}$/.test(revision) || Number(revision) > 2_147_483_647) {
      return { ...result, error: 'Choose a valid template revision.' };
    }
    result.revision = Number(revision);
    result.comparison = await controlApi.templatePreview(token, selected.id, result.revision, result.targetGroup);
    return result;
  } catch (error) {
    if (error instanceof ApiError && error.status === 404) return { ...result, error: 'This template revision or destination is unavailable.' };
    throw error;
  }
}
