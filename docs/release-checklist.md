# Release Checklist

Use this checklist before publishing any new `shroud-privacy` version.

1. Bump versions consistently:
   - `package.json`
   - `package-lock.json`
   - `openclaw.plugin.json`
2. Update `CHANGELOG.md` with:
   - release date
   - CI/workflow changes
   - compatibility notes
3. Declare OpenClaw support explicitly:
   - formal minimum (`openclaw.plugin.json` `compatibility.minOpenClawVersion`)
   - validated matrix (baseline + latest-at-release)
4. Run validation:
   - `npm ci`
   - `npm run lint`
   - `npm run test:unit`
   - `npm run test:integration`
   - `npm run build`
   - compat baseline + latest scenarios
5. Confirm CI on `main` is green and trusted-publisher release succeeded.
