const express = require('express');
const app = express();
app.use(express.json());

app.post('/release-gate', (req, res) => {
  const data = req.body;
  const violations = [];

  // Permissions must be exactly least privilege for a release: contents: read, packages: write, and id-token: none. No additional scopes may be present.
  const perms = data.workflow?.permissions || {};
  const expectedPerms = { contents: 'read', packages: 'write', 'id-token': 'none' };
  
  let hasExcessPermission = false;
  const permKeys = Object.keys(perms);
  if (permKeys.length !== 3) {
    hasExcessPermission = true;
  } else {
    for (const [k, v] of Object.entries(expectedPerms)) {
      if (perms[k] !== v) {
        hasExcessPermission = true;
      }
    }
  }
  
  if (hasExcessPermission) {
    violations.push('EXCESS_PERMISSION');
  }

  // A pull request must use pull_request, never pull_request_target.
  if (data.event === 'pull_request' && data.workflow?.trigger !== 'pull_request') {
    violations.push('UNSAFE_PR_TRIGGER');
  } else if (data.workflow?.trigger === 'pull_request_target') {
    violations.push('UNSAFE_PR_TRIGGER');
  }

  // Tests must pass, the whole matrix must finish, and failFast must be false.
  if (
    data.workflow?.testsPassed !== true ||
    data.workflow?.matrixComplete !== true ||
    data.workflow?.failFast !== false
  ) {
    violations.push('TESTS_INCOMPLETE');
  }

  // Actions owned by actions may use a version tag. Every third-party action must be pinned to a full 40-character lowercase hexadecimal commit SHA.
  const actions = data.workflow?.actions || [];
  let hasMutableAction = false;
  for (const action of actions) {
    if (action.owner !== 'actions') {
      if (!/^[a-f0-9]{40}$/.test(action.ref)) {
        hasMutableAction = true;
      }
    }
  }
  if (hasMutableAction) {
    violations.push('MUTABLE_ACTION');
  }

  // The image must be multi-stage, run as non-root, use either no build secret or a BuildKit secret mount, have zero critical vulnerabilities, and be referenced by digest.
  const image = data.image || {};
  if (image.multiStage !== true) {
    violations.push('SINGLE_STAGE_IMAGE');
  }
  if (image.runsAsRoot !== false) {
    violations.push('ROOT_RUNTIME');
  }
  if (image.secretMode !== 'none' && image.secretMode !== 'buildkit') {
    violations.push('SECRET_IN_LAYER');
  }
  if (image.criticalVulnerabilities !== 0) {
    violations.push('CRITICAL_CVE');
  }
  if (image.digestPinned !== true) {
    violations.push('UNPINNED_IMAGE');
  }

  // Production additionally requires a push on refs/heads/main and an environmentApproval: true field on workflow.
  if (data.target === 'production') {
    if (data.event !== 'push' || data.ref !== 'refs/heads/main') {
      violations.push('INVALID_PRODUCTION_REF');
    }
    if (data.workflow?.environmentApproval !== true) {
      violations.push('APPROVAL_REQUIRED');
    }
  }

  const decision = violations.length === 0 ? 'promote' : 'block';
  res.json({ decision, violations });
});

const PORT = process.env.PORT || 3000;
app.listen(PORT, () => {
  console.log(`Release Gate API listening on port ${PORT}`);
});
