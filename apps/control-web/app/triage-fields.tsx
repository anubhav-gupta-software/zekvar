'use client';

import { useState } from 'react';
import { triageDispositions, triageStatuses, type EventTriage, type TriageAssignee, type TriageDisposition, type TriageStatus } from '../lib/triage';

export function TriageFields({ triage, assignees }: { triage: EventTriage; assignees: TriageAssignee[] }) {
  const [status, setStatus] = useState(triage.status);
  const [disposition, setDisposition] = useState<TriageDisposition | ''>(triage.disposition ?? '');
  const [assignee, setAssignee] = useState(triage.assignee?.id ?? '');
  const current = triage.assignee;
  return <div className="policy-fields">
    <input type="hidden" name="revision" value={triage.revision} />
    <div className="grid gap-1"><label htmlFor="triage-status">Status</label>
      <select id="triage-status" name="status" value={status} onChange={(event) => setStatus(event.target.value as TriageStatus)}>
        {Object.entries(triageStatuses).map(([value, label]) => <option key={value} value={value}>{label}</option>)}
      </select>
    </div>
    <div className="grid gap-1"><label htmlFor="triage-assignee">Assignee</label>
      <select id="triage-assignee" name="assignee" value={assignee} onChange={(event) => setAssignee(event.target.value)}>
        <option value="">Unassigned</option>
        {assignees.map(({ id, name }) => <option key={id} value={id}>{name} ({id.slice(0, 8)})</option>)}
        {current && !assignees.some(({ id }) => id === current.id) &&
          <option value={current.id}>{current.name} (inactive)</option>}
      </select>
    </div>
    {status === 'resolved' && <div className="grid gap-1"><label htmlFor="triage-disposition">Resolution</label>
      <select id="triage-disposition" name="disposition" value={disposition}
        onChange={(event) => setDisposition(event.target.value as TriageDisposition)} required>
        <option value="">Choose a resolution</option>
        {Object.entries(triageDispositions).map(([value, label]) => <option key={value} value={value}>{label}</option>)}
      </select>
    </div>}
  </div>;
}
