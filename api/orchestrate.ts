import crypto from 'crypto';
import Anthropic from '@anthropic-ai/sdk';
import { Octokit } from '@octokit/rest';

// Deterministic sanitizer: ensures raw secrets never reach LLM context windows
function sanitizeDiff(rawDiff: string): string {
  return rawDiff
    // Mask Stripe live/test keys
    .replace(/\b(sk_live_|rk_live_|sk_test_|rk_test_)[0-9a-zA-Z]{10,}\b/g, '$1[REDACTED_BY_SAFEGUARD]')
    // Mask AWS Access Keys
    .replace(/\b(AKIA|ASIA)[0-9A-Z]{16}\b/g, '$1[REDACTED_BY_SAFEGUARD]')
    // Mask generic high-entropy Bearer/API assignments
    .replace(/(api[_-]?key|secret|token|password|service_role)\s*[:=]\s*['"][^'"]{12,}['"]/gi, '$1: "[REDACTED_BY_SAFEGUARD]"');
}

export default async function handler(req: any, res: any) {
  if (req.method !== 'POST') {
    return res.status(405).json({ error: 'Method Not Allowed' });
  }

  const signatureHeader = req.headers['x-safeguard-signature'] || '';
  const hmacSecret = process.env.ORCHESTRATOR_HMAC_SECRET || '';
  const rawBody = typeof req.body === 'string' ? req.body : JSON.stringify(req.body);

  // 1. Cryptographic HMAC Verification
  const expectedSig = 'sha256=' + crypto.createHmac('sha256', hmacSecret).update(rawBody).digest('hex');
  if (!hmacSecret || signatureHeader !== expectedSig) {
    return res.status(401).json({ error: 'Invalid HMAC signature' });
  }

  const payload = typeof req.body === 'string' ? JSON.parse(req.body) : req.body;
  const { repository, commit_sha, gitleaks_status, trufflehog_status, baas_schema_changed } = payload;
  const [owner, repo] = repository.split('/');

  const octokit = new Octokit({ auth: process.env.SAFEGUARD_GITHUB_PAT });
  const anthropic = new Anthropic({ apiKey: process.env.ANTHROPIC_API_KEY });

  try {
    // 2. Fetch the commit diff from GitHub
    const commitData = await octokit.repos.getCommit({
      owner,
      repo,
      ref: commit_sha,
      mediaType: { format: 'diff' }
    });

    const rawDiff = String(commitData.data).slice(0, 35000); // Bound context size
    const safeDiff = sanitizeDiff(rawDiff);

    // 3. AGENT 1: The Infrastructure & BaaS Surgeon
    const surgeonResponse = await anthropic.messages.create({
      model: 'claude-sonnet-4-20250514',
      max_tokens: 1800,
      system: `You are Agent 1 (The BaaS & Code Surgeon) in a production security orchestrator.
Analyze the sanitized git diff and telemetry flags. Check strictly for:
1. Supabase SQL migrations creating tables without 'ENABLE ROW LEVEL SECURITY' or permissive 'USING (true)' write policies.
2. Firebase firestore.rules / storage.rules allowing unauthenticated writes.
3. Stripe or Mux webhook handlers parsing payloads without signature verification.
4. Client-side env exposure (NEXT_PUBLIC_ / VITE_ / EXPO_PUBLIC_ wrapping secret or service_role keys).
5. Hardcoded credentials flagged by Gitleaks/TruffleHog.
Provide: (A) Severity Verdict [CRITICAL | WARNING | FALSE_POSITIVE], (B) Exact Exploit Vector, and (C) Drop-in Code/SQL Remediation Patch.`,
      messages: [
        {
          role: 'user',
          content: `Repo: ${repository}\nCommit: ${commit_sha}\nGitleaks: ${gitleaks_status}\nTruffleHog: ${trufflehog_status}\nBaaS Changed: ${baas_schema_changed}\n\nSanitized Diff:\n${safeDiff}`
        }
      ]
    });

    const surgeonAnalysis = surgeonResponse.content[0].type === 'text' ? surgeonResponse.content[0].text : '';

    // 4. AGENT 2: The Adversarial Judge (Dual-Loop Verification)
    const judgeResponse = await anthropic.messages.create({
      model: 'claude-sonnet-4-20250514',
      max_tokens: 1000,
      system: `You are Agent 2 (The Adversarial Judge). Your job is to stress-test Agent 1's security patch.
Verify whether Agent 1's proposed fix will break legitimate app functionality, lock out authenticated users in RLS, or break Vercel/Netlify builds.
Output a concise final executive ruling and the verified remediation code block.`,
      messages: [
        {
          role: 'user',
          content: `Original Sanitized Diff:\n${safeDiff}\n\nAgent 1 Proposed Audit & Patch:\n${surgeonAnalysis}`
        }
      ]
    });

    const judgeRuling = judgeResponse.content[0].type === 'text' ? judgeResponse.content[0].text : '';

    // 5. Post the Verified Audit Report directly to the GitHub Commit & Open an Issue if Critical
    const reportBody = `## 🛡️ Safeguard Gate 3: Multi-Agent Security Audit
**Commit:** \`${commit_sha}\`
**Deterministic Triggers:** Gitleaks: \`${gitleaks_status}\` | TruffleHog: \`${trufflehog_status}\` | BaaS/Infra Modified: \`${baas_schema_changed}\`

---
### 🔍 Agent 1: BaaS & Code Surgeon Findings
${surgeonAnalysis}

---
### ⚖️ Agent 2: Adversarial Judge Ruling
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
        title: `🚨 [Safeguard Alert] Security intervention required on commit ${commit_sha.slice(0, 7)}`,
        body: reportBody
      });
    }

    return res.status(200).json({ status: 'Audit complete and posted to GitHub' });
  } catch (err: any) {
    console.error('Orchestrator error:', err);
    return res.status(500).json({ error: err.message });
  }
}