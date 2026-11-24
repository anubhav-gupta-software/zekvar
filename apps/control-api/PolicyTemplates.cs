namespace Control;

internal sealed record PolicyTemplate(Guid Id, string Name, int Revision, int SourceVersion);
internal sealed record PolicyTemplateRevision(int Revision, int SourceVersion, DateTime CreatedAt);
internal sealed record PolicyTemplateDetails(PolicyTemplate Template, IReadOnlyList<PolicyTemplateRevision> Revisions);
internal sealed record PolicyTemplateOrigin(Guid TemplateId, string Name, int Revision, int SourceVersion);
internal sealed record PolicyTemplatePreview(PolicyTemplateOrigin Template, string? GroupName, Policy Before, Policy Candidate);
internal sealed record PolicyTemplateAudit(string Operation, PolicyTemplateOrigin Template, Guid? GroupId = null, int? PublishedVersion = null);
internal sealed record PolicyTemplateResult(PolicyTemplate? Template = null, string? Error = null);

internal sealed record CreatePolicyTemplate(string? Name, int SourceVersion);
internal sealed record RevisePolicyTemplate(int ExpectedRevision, int SourceVersion);
internal sealed record ArchivePolicyTemplate(int ExpectedRevision);
internal sealed record ApplyPolicyTemplate(int Revision, Guid? GroupId, int ExpectedVersion);
