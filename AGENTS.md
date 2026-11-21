# Repository instructions

After each completed task, append a dated entry to the Decision log in `product_plan.md`. Record what changed, why, how it was verified, and any open items. Log material decisions as they arise. Mark proposals and superseded decisions explicitly. Update the relevant plan sections when scope, architecture, pricing, or launch criteria change.

## Testing product changes

- Exercise the changed workflow from its normal entry point through its observable result. Use the real browser, API, and database for the parts involved when available. Include the supported layout and input variants that the change can affect.
- Run relevant regression tests and cover realistic failure paths. Check rejection and recovery, retries and duplicate actions, permission boundaries, and sensitive-data handling wherever the change affects them. Add a regression case for a reported bug when the existing suite would miss it.
- Record which scenarios passed and which remain unverified. Identify controlled fixtures and live-site checks by name. When live testing is blocked, record the blocker and the exact behavior still to confirm. Use synthetic data for security tests.

## Commits

After verifying each completed product change, create a local Git commit that includes its decision-log entry. Keep unrelated workspace changes out of the commit.

Push each verified commit to the GitHub branch configured for this checkout when its destination is known and authorized. Record any missing remote or push blocker.
