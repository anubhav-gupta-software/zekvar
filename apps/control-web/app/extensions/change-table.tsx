import { installTypeLabels, siteAccessLabels, type InventoryExtensionChange } from '../../lib/extension-inventory';

export function ExtensionChangesTable({ changes, label, names }: {
  changes: InventoryExtensionChange[];
  label: string;
  names?: ReadonlyMap<string, string>;
}) {
  return <div className="table-scroll" tabIndex={0} role="region" aria-label={label}>
    <table className="extension-changes-table" aria-label={label}>
      <thead><tr><th>Extension</th><th>Action</th><th>Changes</th><th>Review</th></tr></thead>
      <tbody>{changes.map((change) =>
        <ExtensionChangeRow key={change.extensionId} change={change} name={names?.get(change.extensionId)} />)}</tbody>
    </table>
  </div>;
}

function ExtensionChangeRow({ change, name }: { change: InventoryExtensionChange; name?: string }) {
  const { before, after, extensionId } = change;
  const fields: [string, string | undefined, string | undefined][] = [
    ['Version', before?.version, after?.version],
    ['State', before ? (before.enabled ? 'Enabled' : 'Disabled') : undefined, after ? (after.enabled ? 'Enabled' : 'Disabled') : undefined],
    ['Install source', before ? installTypeLabels[before.installType] : undefined, after ? installTypeLabels[after.installType] : undefined],
    ['Site access', before ? siteAccessLabels[before.siteAccess] : undefined, after ? siteAccessLabels[after.siteAccess] : undefined],
    ['Selected API permissions', before ? before.permissions.join(', ') || 'None reported' : undefined,
      after ? after.permissions.join(', ') || 'None reported' : undefined],
  ];
  return <tr>
    <th scope="row">{name && <>{name}<br /></>}<code title={extensionId}>{extensionId}</code></th>
    <td>{!before ? 'Added' : !after ? 'Removed' : 'Updated'}</td>
    <td><ul>{fields.filter(([, prior, next]) => prior !== next).map(([field, prior, next]) => <li key={field}>
      <strong>{field}</strong> {prior && next ? `${prior} → ${next}` : prior ?? next}
    </li>)}</ul></td>
    <td>{change.reviewAccess ? <span className="badge warn">Review access</span> : '—'}</td>
  </tr>;
}
