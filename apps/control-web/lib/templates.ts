import type { Policy } from './control';

export type PolicyTemplate = { id: string; name: string; revision: number; sourceVersion: number };
export type PolicyTemplateOrigin = { templateId: string; name: string; revision: number; sourceVersion: number };
export type PolicyTemplateDetails = {
  template: PolicyTemplate; revisions: { revision: number; sourceVersion: number; createdAt: string }[];
};
export type PolicyTemplatePreview = { template: PolicyTemplateOrigin; groupName: string | null; before: Policy; candidate: Policy };
export type PolicyTemplateAudit = {
  operation: 'created' | 'revised' | 'archived' | 'applied'; template: PolicyTemplateOrigin; groupId: string | null; publishedVersion: number | null;
};
