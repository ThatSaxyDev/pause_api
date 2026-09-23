export type TrustedOrganisation = {
  id: string;
  name: string;
  aliases: string[];
  domains: string[];
  officialUrl: string;
  category: 'government' | 'financial';
  sourceUrl: string;
  verifiedAt: string;
  reviewDueAt: string;
};

// Curated evidence data, not detection logic. The engine works without any
// entry here; an entry merely lets Pause name a verified official destination.
// New entries require independent verification and a review date/owner before
// this MVP moves to a managed registry.
export const trustedOrganisations: TrustedOrganisation[] = [
  {
    id: 'frsc',
    name: 'Federal Road Safety Corps',
    aliases: ['frsc', 'federal road safety corps'],
    domains: ['frsc.gov.ng'],
    officialUrl: 'https://frsc.gov.ng',
    category: 'government',
    sourceUrl: 'https://frsc.gov.ng/post/frsc-alerts-motorists-to-fraudulent-sms-fake-website-disowns-scam-messages-on-road-traffic-offences',
    verifiedAt: '2026-09-23',
    reviewDueAt: '2026-12-23',
  },
  {
    id: 'cbn',
    name: 'Central Bank of Nigeria',
    aliases: ['cbn', 'central bank of nigeria'],
    domains: ['cbn.gov.ng'],
    officialUrl: 'https://www.cbn.gov.ng',
    category: 'government',
    sourceUrl: 'https://www.cbn.gov.ng/Out/2024/CCD/CBN%20Press%20Release%20301124%20%20%28Website%20Redesign%29%20.pdf',
    verifiedAt: '2026-09-23',
    reviewDueAt: '2026-12-23',
  },
  {
    id: 'efcc',
    name: 'Economic and Financial Crimes Commission',
    aliases: ['efcc', 'economic and financial crimes commission'],
    domains: ['efcc.gov.ng'],
    officialUrl: 'https://efcc.gov.ng',
    category: 'government',
    sourceUrl: 'https://efcc.gov.ng/',
    verifiedAt: '2026-09-23',
    reviewDueAt: '2026-12-23',
  },
  {
    id: 'nimc',
    name: 'National Identity Management Commission',
    aliases: ['nimc', 'national identity management commission'],
    domains: ['nimc.gov.ng'],
    officialUrl: 'https://www.nimc.gov.ng',
    category: 'government',
    sourceUrl: 'https://nimc.gov.ng/',
    verifiedAt: '2026-09-23',
    reviewDueAt: '2026-12-23',
  },
];
