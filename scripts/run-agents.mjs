import fs from 'fs';
import { Anthropic } from '@anthropic-ai/sdk';
import { Octokit } from '@octokit/rest';

function sanitizeDiff(rawDiff) {
  return rawDiff
    .replace(/\b(sk_live_|rk_live_|sk_test_|rk_test_)[0-9a-zA-Z]{10,}\b/g, '$1[REDACTED_BY_SAFEGUARD]')
    .replace(/\b(AKIA|ASIA)[0-9A-Z]{16}\b/g, '$1[REDACTED_BY_SAFEGUARD]')
    .replace(/(api[_-]?key|secret|token|password|service_role)\s*[:=]\s*['"][^'"]{12,}['"]/gi, '$1: "[REDACTED_BY_SAFEGUARD]"');
}

async function runOrchestrator() {
  const repository = process.env.GITHUB_REPOSITORY || '';
  const commit_sha = process.env.GITHUB_SHA || '';
  const gitleaks_status = process.env.GITLEAKS_STATUS || 'success';
  const trufflehog_status = process.env.TRUFFLEHOG_STATUS || 'success';
  const baas_schema_changed = process.env.BAAS_MODIFIED || 'false';

  const [owner, repo] = repository.split('/');
  const octokit = new Octokit({ auth: process.env.GITHUB_TOKEN });
  const anthropic = new Anthropic({ apiKey: (process.env.ANTHROPIC_API_KEY || '').trim() });

  const rawDiff = fs.existsSync('/tmp/commit.diff')
    ? fs.readFileSync('/tmp/commit.diff', 'utf8').slice(0, 35000)
    : 'No diff available';
  const safeDiff = sanitizeDiff(rawDiff);

  console.log('Running Agent 1 (BaaS & Code Surgeon)...');
  const surgeonResponse = await anthropic.messages.create({
    model: 'claude-sonnet-5-5',
    max_tokens: 4096,
    system: `You are Agent 1 (The BaaS & Code Surgeon).
Analyze the sanitized git diff. Check strictly for Supabase/Firebase RLS vulnerabilities, unverified webhooks, and exposed env vars.
CRITICAL INSTRUCTION: Be extremely concise. Do not write an essay.
Provide exactly: (A) Severity Verdict [CRITICAL | WARNING | FALSE_POSITIVE], (B) Exact Exploit Vector (1 sentence), and (C) Drop-in Code/SQL Remediation Patch.`,
    messages: [
      {
        role: 'user',
        content: `Repo: ${repository}\nCommit: ${commit_sha}\nGitleaks: ${gitleaks_status}\nTruffleHog: ${trufflehog_status}\nBaaS Changed: ${baas_schema_changed}\n\nSanitized Diff:\n${safeDiff}`
      }
    ]
  });

  console.log('--- SURGEON RAW API RESPONSE ---');
  console.log(JSON.stringify(surgeonResponse, null, 2));

  const surgeonAnalysis = surgeonResponse?.content?.map(c => c.text)?.join('\n') || JSON.stringify(surgeonResponse?.content || surgeonResponse);

  console.log('Running Agent 2 (Adversarial Judge)...');
  const judgeResponse = await anthropic.messages.create({
    model: 'claude-sonnet-5-5',
    max_tokens: 4096,
    system: `You are Agent 2 (The Adversarial Judge). 
Stress-test Agent 1's security patch. Will it break legitimate app functionality?
CRITICAL INSTRUCTION: Be extremely concise. 
Output a 2-sentence final executive ruling and the verified remediation code block.`,
    messages: [
      {
        role: 'user',
        content: `Original Sanitized Diff:\n${safeDiff}\n\nAgent 1 Proposed Audit & Patch:\n${surgeonAnalysis}`
      }
    ]
  });

  console.log('--- JUDGE RAW API RESPONSE ---');
  console.log(JSON.stringify(judgeResponse, null, 2));

  const judgeRuling = judgeResponse?.content?.map(c => c.text)?.join('\n') || JSON.stringify(judgeResponse?.content || judgeResponse);

  const reportBody = `## ðŸ›¡ï¸ Safeguard Gate 3: Multi-Agent Security Audit
**Commit:** \`${commit_sha}\`
**Deterministic Triggers:** Gitleaks: \`${gitleaks_status}\` | TruffleHog: \`${trufflehog_status}\` | BaaS/Infra Modified: \`${baas_schema_changed}\`

---
### ðŸ” Agent 1: BaaS & Code Surgeon Findings
${surgeonAnalysis}

---
### âš–ï¸ Agent 2: Adversarial Judge Ruling
${judgeRuling}`;

  await octokit.repos.createCommitComment({
    owner,
    repo,
    commit_sha,
    body: reportBody
  });

  if (gitleaks_status === 'failure' || trufflehog_status === 'failure' || surgeonAnalysis.includes('CRITICAL')) {
    await octokit.issues.create({
      owner,
      repo,
      title: `ðŸš¨ [Safeguard Alert] Security intervention required on commit ${commit_sha.slice(0, 7)}`,
      body: reportBody
    });
    console.log(`Opened Security Alert Issue!`);
  }
}

runOrchestrator().catch((err) => {
  console.error('Orchestrator error:', err);
  process.exit(1);
});