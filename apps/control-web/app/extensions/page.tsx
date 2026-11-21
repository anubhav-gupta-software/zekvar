import { redirect } from 'next/navigation';
import type { InventoryExtension } from '../../../../contracts/policy/extension-inventory';
import { ApiError, controlApi } from '../../lib/api';
import { isId, utc } from '../../lib/control';
import { installTypeLabels, inventoryStatusLabels, needsReview, siteAccessLabels, type InventoryInstallation } from '../../lib/extension-inventory';
import { sessionToken } from '../../lib/session';
import { RefreshSection } from '../forms';
import { Sidebar } from '../workspace';

export default async function ExtensionsPage({ searchParams }: { searchParams: Promise<{ browser?: string | string[] }> }) {
  const token = await sessionToken();
  if (!token) redirect('/');
  const { browser } = await searchParams;
  const data = await loadInventory(token, browser).catch((error) => {
    if (error instanceof ApiError && error.status === 401) redirect('/');
    if (error instanceof ApiError) return undefined;
    throw error;
  });
  return <div className="workspace">
    <Sidebar active="extensions" session={data?.session} />
    <main className="dashboard">
      <header className="page-heading">
        <div>{data && <p className="eyebrow">{data.session.organization}</p>}<h1>Browser extensions</h1></div>
        <span className="badge local"><span aria-hidden="true" />Local demo</span>
      </header>
      {data ? <>
        <section className="panel table-panel" aria-labelledby="inventory-heading">
          <div className="panel-heading">
            <h2 id="inventory-heading">Browser inventory status</h2>
            <RefreshSection label="Refresh extension inventory" />
          </div>
          <div className="table-scroll" tabIndex={0} role="region" aria-labelledby="inventory-heading">
            <table aria-labelledby="inventory-heading">
              <thead><tr><th>Installation</th><th>Rollout group</th><th>Status</th><th>Extensions</th><th>Reported (UTC)</th></tr></thead>
              <tbody>{data.installations.map((row) => <tr key={row.installationId}>
                <th scope="row"><a className="underline" href={`/extensions?browser=${row.installationId}#extension-details`}
                  aria-current={data.selected?.installationId === row.installationId ? 'true' : undefined}
                  aria-label={`View extensions for ${row.installationId}`} title={row.installationId}>
                  <code>{row.installationId.slice(0, 13)}</code></a></th>
                <td>{row.groupName ?? 'Organization baseline'}</td>
                <td><span className={`badge ${row.status === 'reported' ? 'current' : ''}`}>{inventoryStatusLabels[row.status]}</span></td>
                <td>{row.status === 'reported' ? row.extensionCount + row.omitted : '—'}</td>
                <td>{row.reportedAt ? <time dateTime={row.reportedAt}>{utc.format(new Date(row.reportedAt))}</time> : '—'}</td>
              </tr>)}</tbody>
            </table>
          </div>
          {data.installations.length === 0 && <p className="empty">No active browsers are enrolled.</p>}
        </section>
        {data.selected ? <BrowserInventory inventory={data.selected} /> :
          data.unavailable ? <section className="panel" role="alert">The selected browser is unavailable.</section> : null}
      </> : <section className="panel" role="alert">Control could not load extension inventory. Try reloading this page.</section>}
    </main>
  </div>;
}

async function loadInventory(token: string, browser: string | string[] | undefined) {
  const [session, installations] = await Promise.all([controlApi.session(token), controlApi.extensionInventory(token)]);
  const id = browser === undefined ? installations[0]?.installationId : isId(browser) ? browser : undefined;
  const selected = id ? await controlApi.browserExtensionInventory(token, id).catch((error) => {
    if (error instanceof ApiError && error.status === 404) return undefined;
    throw error;
  }) : undefined;
  return { session, installations, selected, unavailable: browser !== undefined && !selected };
}

const emptyMessages = {
  off: 'Enable Extension inventory in the policy assigned to this browser.',
  awaiting: 'Waiting for this browser to report under its current policy.',
  permission_required: 'In the Zekvar Browser popup, select Allow extension inventory and confirm in Chrome.',
  unavailable: 'This browser reported that collection was unavailable. Sync it again to retry.',
  reported: 'Chrome reported no other browser extensions.',
};

function BrowserInventory({ inventory }: { inventory: InventoryInstallation }) {
  const entries = [...inventory.entries ?? []].sort((left, right) => left.name.localeCompare(right.name) || left.id.localeCompare(right.id));
  return <section className="panel table-panel" id="extension-details" aria-labelledby="extension-heading">
    <div className="panel-heading"><h2 id="extension-heading">Extensions on <code>{inventory.installationId.slice(0, 13)}</code></h2></div>
    {entries.length > 0 ? <>
      <div className="table-scroll" tabIndex={0} role="region" aria-labelledby="extension-heading">
        <table aria-labelledby="extension-heading">
          <thead><tr><th>Extension</th><th>Version</th><th>State</th><th>Install source</th><th>Site access</th><th>Selected API permissions</th><th>Review</th></tr></thead>
          <tbody>{entries.map((extension) => <ExtensionRow key={extension.id} extension={extension} />)}</tbody>
        </table>
      </div>
      <p className="empty">{inventory.omitted > 0 ? `Showing ${entries.length} extensions. ${inventory.omitted} omitted from this report. ` : ''}
        Review flags reflect permission or install-source signals.</p>
    </> : <p className="empty">{emptyMessages[inventory.status]}</p>}
  </section>;
}

function ExtensionRow({ extension }: { extension: InventoryExtension }) {
  return <tr>
    <th scope="row" className="emphasis">{extension.name}<br /><code title={extension.id}>{extension.id}</code></th>
    <td>{extension.version}</td>
    <td>{extension.enabled ? 'Enabled' : 'Disabled'}</td>
    <td>{installTypeLabels[extension.installType]}</td>
    <td>{siteAccessLabels[extension.siteAccess]}</td>
    <td>{extension.permissions.length ? extension.permissions.join(', ') : 'None reported'}</td>
    <td>{needsReview(extension) ? <span className="badge warn">Review</span> : '—'}</td>
  </tr>;
}
