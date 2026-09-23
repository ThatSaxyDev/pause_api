import { domainToASCII } from 'node:url';

import { trustedOrganisations, type TrustedOrganisation } from './data/trusted-organisations.js';

export type RiskLevel = 'high' | 'caution' | 'unable_to_verify' | 'no_known_warning_found';
export type EvidenceSeverity = 'high' | 'medium' | 'low';
export type Evidence = {
  kind: string;
  severity: EvidenceSeverity;
  title: string;
  detail: string;
};

export type Analysis = {
  analysisId: string;
  policyVersion: string;
  risk: { level: RiskLevel; score: number; summary: string; guidance: string };
  urls: Array<{ original: string; host?: string; asciiHost?: string }>;
  evidence: Evidence[];
  safeActions: Array<{ type: 'open_verified_site'; label: string; url: string }>;
};

const urlPattern = /(?:https?:\/\/|www\.)[^\s<>()]+|\b(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z]{2,}(?::\d{1,5})?(?:\/[^\s<>()]*)?/gi;
const urgencyPattern = /\b(urgent|immediately|action required|final warning|offence|penalty|suspend(?:ed)?|within \d+ hours?)\b/i;
const sensitiveRequestPattern = /\b(otp|one[- ]time password|pin|password|cvv|bank(?:ing)? details|card details|pay(?:ment)? now|transfer money)\b/i;
const shortenerHosts = new Set(['bit.ly', 'tinyurl.com', 't.co', 'is.gd', 'cutt.ly', 'rb.gy', 'shorturl.at']);
const highRiskTlds = new Set(['top', 'xyz', 'click', 'vip', 'live', 'site', 'online', 'shop', 'info']);
const deceptiveHostTerms = new Set(['account', 'auth', 'bonus', 'claim', 'confirm', 'login', 'pay', 'payment', 'portal', 'secure', 'support', 'update', 'verify', 'wallet']);

function cleanUrl(value: string): string {
  return value.replace(/[),.;!?]+$/, '');
}

function extractUrls(value: string): string[] {
  // Bound third-party enrichment work and keep results legible on mobile.
  return [...value.matchAll(urlPattern)].slice(0, 10).map((match) => cleanUrl(match[0]!));
}

function asUrl(value: string): URL | undefined {
  try {
    return new URL(/^https?:\/\//i.test(value) ? value : `https://${value}`);
  } catch {
    return undefined;
  }
}

function compact(value: string): string {
  return value.toLowerCase().replace(/[^a-z0-9]/g, '');
}

function organisationClaimed(value: string, organisation: TrustedOrganisation): boolean {
  const lower = value.toLowerCase();
  return organisation.aliases.some((alias) => lower.includes(alias));
}

function resemblesOfficialHost(host: string, organisation: TrustedOrganisation): boolean {
  const candidate = compact(host);
  return organisation.domains.some((domain) => {
    const official = compact(domain);
    const stem = official.replace(/(?:com|org|gov|ng|uk|au)$/g, '');
    return candidate !== official && stem.length >= 4 && candidate.includes(stem);
  });
}

function hasDeceptiveHostShape(host: string): boolean {
  const labels = host.split('.');
  const tld = labels.at(-1) ?? '';
  const hasDeceptiveTerm = labels.some((label) => deceptiveHostTerms.has(label))
      || labels.some((label) => [...deceptiveHostTerms].some((term) => label.includes(term)));
  // A suspicious term alone is common on legitimate sites. It becomes useful
  // evidence only when paired with a low-trust TLD or a compound disguise.
  return hasDeceptiveTerm && (highRiskTlds.has(tld) || labels.length >= 3);
}

function addEvidence(list: Evidence[], item: Evidence): void {
  if (!list.some((existing) => existing.kind === item.kind && existing.detail === item.detail)) list.push(item);
}

export function analyseInput(value: string, id: string = crypto.randomUUID()): Analysis {
  const evidence: Evidence[] = [];
  const safeActions: Analysis['safeActions'] = [];
  const urls: Analysis['urls'] = [];
  let score = 0;

  for (const original of extractUrls(value)) {
    const parsed = asUrl(original);
    if (!parsed) {
      addEvidence(evidence, {
        kind: 'malformed_url', severity: 'medium', title: 'This link is malformed',
        detail: 'The address could not be read safely. Do not open it until you verify the source independently.',
      });
      score += 20;
      urls.push({ original });
      continue;
    }

    const host = parsed.hostname.toLowerCase();
    const asciiHost = domainToASCII(host) || host;
    urls.push({ original, host, asciiHost });

    if (parsed.username || parsed.password) {
      addEvidence(evidence, {
        kind: 'embedded_credentials', severity: 'high', title: 'This link hides information before the real address',
        detail: 'The link contains embedded credentials, a technique often used to make a destination look trustworthy.',
      });
      score += 50;
    }
    if (/^\d{1,3}(?:\.\d{1,3}){3}$/.test(host) || host.includes(':')) {
      addEvidence(evidence, {
        kind: 'literal_ip_host', severity: 'medium', title: 'This link uses an IP address instead of a normal website name',
        detail: 'Unexpected requests should normally lead to a recognisable official domain.',
      });
      score += 20;
    }
    if (parsed.port && !['80', '443'].includes(parsed.port)) {
      addEvidence(evidence, {
        kind: 'unusual_port', severity: 'low', title: 'This link uses an unusual connection port',
        detail: 'An unusual port is not proof of fraud, but it deserves extra verification.',
      });
      score += 10;
    }
    if (shortenerHosts.has(host)) {
      addEvidence(evidence, {
        kind: 'url_shortener', severity: 'medium', title: 'This shortened link hides its destination',
        detail: 'Do not open a shortened link from an unexpected message until you verify who sent it.',
      });
      score += 20;
    }
    if (hasDeceptiveHostShape(host)) {
      addEvidence(evidence, {
        kind: 'deceptive_host_shape', severity: 'medium', title: 'This address uses a common impersonation pattern',
        detail: 'Names combined with terms like “verify”, “secure”, “payment”, or “login” can be used to make a fake site look official.',
      });
      score += 20;
    }
    if (host !== asciiHost || /[^\x00-\x7F]/.test(host) || /[\u200B-\u200F\u202A-\u202E\u2060]/.test(original)) {
      addEvidence(evidence, {
        kind: 'unicode_or_invisible_characters', severity: 'high', title: 'This link uses unusual characters',
        detail: 'Lookalike or invisible characters can make a fake address resemble a trusted one.',
      });
      score += 50;
    }

    for (const organisation of trustedOrganisations) {
      const isOfficial = organisation.domains.some((domain) => host === domain || host.endsWith(`.${domain}`));
      const claimed = organisationClaimed(value, organisation);
      if (!isOfficial && (claimed || resemblesOfficialHost(host, organisation))) {
        const officialDomain = organisation.domains[0]!;
        addEvidence(evidence, {
          kind: 'official_domain_mismatch', severity: 'high', title: `This is not ${organisation.name}'s official domain`,
          detail: `The message uses ${host}. ${organisation.name}'s verified domain is ${officialDomain}.`,
        });
        score += 60;
        if (!safeActions.some((action) => action.url === organisation.officialUrl)) {
          safeActions.push({ type: 'open_verified_site', label: `Visit the official ${organisation.name} website`, url: organisation.officialUrl });
        }
      }
    }
  }

  if (urgencyPattern.test(value)) {
    addEvidence(evidence, {
      kind: 'urgency', severity: 'medium', title: 'The message uses pressure to rush you',
      detail: 'Unexpected urgent requests should be verified through an official channel before you act.',
    });
    score += 15;
  }
  if (sensitiveRequestPattern.test(value)) {
    addEvidence(evidence, {
      kind: 'sensitive_data_request', severity: 'medium', title: 'The message may be asking for sensitive information or money',
      detail: 'Do not share codes, passwords, banking details, or make a payment through an unexpected message.',
    });
    score += 25;
  }

  const risk: Analysis['risk'] = score >= 60
      ? { level: 'high', score, summary: 'Likely scam or organisation impersonation.', guidance: 'Do not open the link, pay, or share any codes. Verify independently using an official channel.' }
      : score >= 30
      ? { level: 'caution', score, summary: 'This needs independent verification.', guidance: 'Do not act through this message. Verify the request through an official channel you find yourself.' }
      : evidence.length > 0
      ? { level: 'caution', score, summary: 'There are warning signs worth checking.', guidance: 'Treat unexpected requests carefully and verify before you respond.' }
      : urls.length === 0
      ? { level: 'unable_to_verify', score, summary: 'Pause could not find a link or a strong warning in this text.', guidance: 'This is not a safety verdict. Verify unexpected requests through an official channel.' }
      : { level: 'no_known_warning_found', score, summary: 'No known warning was found.', guidance: 'This is not a guarantee. Still verify unexpected requests through an official channel.' };

  return { analysisId: id, policyVersion: '2026-09-mvp.2', risk, urls, evidence, safeActions };
}
