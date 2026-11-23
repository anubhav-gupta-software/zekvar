import { caseNumber, caseOperations, casePath, type CaseChange } from '../../lib/cases';
import { eventPath, triageDispositions, triageStatuses } from '../../lib/triage';

export function CaseActivityDetails({ change, showCase = false }: { change: CaseChange; showCase?: boolean }) {
  return <>
    {showCase && <><a className="underline" href={casePath(change.caseId)}>{caseNumber(change.caseId)}</a>{' · '}</>}
    {caseOperations[change.operation]}
    {change.before && change.after && change.before.status !== change.after.status &&
      <> · {triageStatuses[change.before.status]} → {triageStatuses[change.after.status]}</>}
    {change.after?.disposition && <> · {triageDispositions[change.after.disposition]}</>}
    {change.before?.assigneeId !== change.after?.assigneeId && change.before && <> · Assignment changed</>}
    {change.installationId && change.eventId && <>
      {' · '}<a className="underline" href={eventPath(change.installationId, change.eventId)}>Review event</a>
    </>}
  </>;
}
