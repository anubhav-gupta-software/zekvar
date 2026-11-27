# Zekvar customer documentation

These documents help a customer IT or security team deploy, evaluate, and operate Zekvar Browser and Control. They describe what the product does today. Deep operator detail stays in the component READMEs linked from each page.

Status: Browser v0.45.0, design-partner pilot preparation. Live signed-in app coverage is not yet verified. Items marked **[TO CONFIRM]** are company commitments not yet made.

| Document | Use it to |
| --- | --- |
| [Install, upgrade, roll back, and remove](install-and-remove.md) | Deploy the signed extension with Chrome enterprise policy, enroll browsers, verify in Control, upgrade, roll back, and remove it. |
| [Security and privacy answers](security-and-privacy.md) | Answer a vendor security questionnaire: data flow, local and sent data, encryption, tenant isolation, access control, audit, retention, permissions, third-party components. |
| [Customer onboarding and pilot guide](onboarding.md) | Run kickoff, pick the pilot group, run the monitor-mode baseline, review results, move to Warn or Block, and decide. |
| [Support and incident response](support-and-incident-response.md) | Open a ticket, assess severity, triage common problems, disable and restore a broken adapter, notify customers, and run the release-blocker runbooks and drills. |
| [App-by-action coverage](coverage.md) | See, for ChatGPT, Gemini, and Claude, which actions and modes are supported, experimental, or unsupported, the minimum Browser version, and the named tests behind each. All evidence is from controlled fixtures. Live signed-in evidence does not exist yet. |
| [HIPAA readiness checklist](hipaa-readiness.md) | Prepare for healthcare buyers: business associate determination, BAA needs, risk analysis, safeguards mapped to product controls, and what "no PHI reaches Control" does and does not cover. Separates product capability from compliance status. |

## Operator references

- [Browser extension README](../apps/browser-extension/README.md)
- [Control dashboard README](../apps/control-web/README.md)
- [Control API README](../apps/control-api/README.md)
- [TLS pilot and signed distribution README](../deploy/pilot/README.md)
- [Product plan](../product_plan.md)
