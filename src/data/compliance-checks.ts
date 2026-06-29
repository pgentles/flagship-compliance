export interface ComplianceCheck {
  id: string;
  regulation: string;
  section: string;
  title: string;
  description: string;
  severity: 'critical' | 'high' | 'medium' | 'low';
  category: string;
  requirements: string[];
  commonViolations: string[];
  penalties: string;
  remediationSteps: string[];
  applicableTo: string[];
}

export interface ComplianceRequest {
  website?: string;
  industry?: string;
  practices?: string[];
  dataTypes?: string[];
  dataType?: string;
  state?: string;
}

export interface ComplianceReport {
  totalChecks: number;
  passed: number;
  failed: number;
  warnings: number;
  riskScore: number;
  findings: Array<{
    check: ComplianceCheck;
    status: 'pass' | 'fail' | 'warning';
    notes?: string;
  }>;
  executiveSummary: string;
  nextSteps: string[];
}

// ─── GLBA (Gramm-Leach-Bliley Act) ────────────────────────────────
const GLBA_CHECKS: ComplianceCheck[] = [
  {
    id: 'glba-privacy-notice',
    regulation: 'GLBA',
    section: '503(a)',
    title: 'Privacy Notice Delivery',
    description: 'Financial institutions must provide clear privacy notices to customers about information collection and sharing practices.',
    severity: 'critical',
    category: 'Disclosure & Transparency',
    requirements: [
      'Provide initial privacy notice before establishing customer relationship',
      'Provide annual privacy notice if non-public personal information is shared',
      'Notice must describe information collected, sharing practices, and opt-out rights',
      'Notice must be clear and conspicuous and in writing if electronic delivery',
    ],
    commonViolations: [
      'No privacy notice on website',
      'Generic boilerplate that does not describe actual practices',
      'Notice buried in terms of service instead of standalone disclosure',
      'No opt-out mechanism provided',
    ],
    penalties: 'Civil penalties: Up to $100,000 per violation for institutions; officers/directors personally liable up to $10,000 per violation.',
    remediationSteps: [
      'Draft comprehensive privacy notice covering all data categories',
      'Implement clear conspicuous notice placement on homepage',
      'Set up annual notice delivery process',
      'Implement opt-out mechanism (online form, toll-free number)',
    ],
    applicableTo: ['Banks', 'Lenders', 'Mortgage companies', 'Investment firms', 'Insurance companies', 'Financial advisors', 'Auto finance companies'],
  },
  {
    id: 'glba-safeguards-rule',
    regulation: 'GLBA',
    section: '501(b)',
    title: 'Safeguards Rule',
    description: 'Financial institutions must develop a comprehensive security plan to protect customer information.',
    severity: 'critical',
    category: 'Data Security',
    requirements: [
      'Develop written information security program',
      'Designate employee(s) to coordinate the program',
      'Identify and assess customer information risks',
      'Regularly test and monitor program effectiveness',
      'Update program in response to changes',
    ],
    commonViolations: [
      'No written security program',
      'No designated security coordinator',
      'No regular testing or monitoring',
      'Program not updated after security incidents',
    ],
    penalties: 'Enforcement by FTC; can result in consent orders and civil penalties.',
    remediationSteps: [
      'Draft comprehensive written information security program',
      'Designate GLBA security officer',
      'Conduct risk assessment of all customer data systems',
      'Implement regular penetration testing schedule',
    ],
    applicableTo: ['All financial institutions (broadly defined)'],
  },
  {
    id: 'glba-prep-texting',
    regulation: 'GLBA',
    section: 'Pretexting Protection',
    title: 'Social Engineering & Pretexting Protection',
    description: 'Prohibit pretexting — obtaining customer information through false pretenses or from unauthorized employees.',
    severity: 'high',
    category: 'Fraud Prevention',
    requirements: [
      'Train employees on social engineering detection',
      'Restrict access to customer information to authorized personnel',
      'Implement identity verification before releasing customer information',
      'Maintain audit trails for customer data access',
    ],
    commonViolations: [
      'No pretexting awareness training',
      'Customer information accessible to all employees',
      'No identity verification before data release',
      'No monitoring of customer data access',
    ],
    penalties: 'Criminal penalties: Up to 5 years imprisonment and fines for pretexting.',
    remediationSteps: [
      'Implement all-hands social engineering training',
      'Restrict PII access to need-to-know basis',
      'Implement knowledge-based authentication for phone/email support',
      'Log and audit all customer data access',
    ],
    applicableTo: ['All financial institutions'],
  },
];

// ─── SOX (Sarbanes-Oxley Act) ─────────────────────────────────────
const SOX_CHECKS: ComplianceCheck[] = [
  {
    id: 'sox-internal-controls',
    regulation: 'SOX',
    section: '404',
    title: 'Internal Control Assessment',
    description: 'Public companies must assess and report on the effectiveness of internal controls over financial reporting.',
    severity: 'critical',
    category: 'Financial Reporting',
    requirements: [
      'Document internal controls over financial reporting',
      'Assess control effectiveness as of fiscal year-end',
      'CEO/CFO certification of reports',
      'External auditor attestation (if accelerated filer)',
    ],
    commonViolations: [
      'No formal control documentation',
      'Control deficiencies not disclosed',
      'Management missing certifications',
      'Auditor attestation not obtained when required',
    ],
    penalties: 'Criminal penalties for false certification: up to $5M fine and 20 years imprisonment for CEOs/CFOs.',
    remediationSteps: [
      'Map all financial reporting processes and key controls',
      'Document controls with risk matrices',
      'Perform gap analysis against COSO framework',
      'Engage external auditor for attestation',
    ],
    applicableTo: ['Public companies', 'Companies preparing for IPO', 'Wholly-owned subsidiaries of public companies'],
  },
  {
    id: 'sox-audit-committee',
    regulation: 'SOX',
    section: '301',
    title: 'Audit Committee Independence',
    description: 'Audit committee must be composed entirely of independent directors and directly responsible for auditor appointment.',
    severity: 'high',
    category: 'Corporate Governance',
    requirements: [
      'All audit committee members must be independent',
      'At least one member must be a financial expert',
      'Committee directly appoints and oversees auditors',
      'Committee must establish complaint handling procedures',
    ],
    commonViolations: [
      'Non-independent board members on audit committee',
      'No financial expert on committee',
      'Management instead of committee selects auditor',
      'No whistleblower channel for accounting concerns',
    ],
    penalties: 'SEC enforcement; potential delisting; officer/director bars.',
    remediationSteps: [
      'Audit current committee composition against independence standards',
      'Identify qualified independent financial expert',
      'Formalize committee charter with auditor oversight authority',
      'Establish anonymous reporting hotline for accounting/audit concerns',
    ],
    applicableTo: ['Public companies listed on US exchanges'],
  },
  {
    id: 'sox-record-retention',
    regulation: 'SOX',
    section: '802',
    title: 'Record Retention Requirements',
    description: 'SOX requires retention of audit work papers and documents supporting financial reports for 7 years.',
    severity: 'high',
    category: 'Records Management',
    requirements: [
      'Retain audit work papers for 7 years',
      'Retain documents supporting financial reports for 7 years',
      'Database backups must be maintained',
      'Email retention policy aligned with SOX record classes',
    ],
    commonViolations: [
      'Email auto-delete policies shorter than 7 years',
      'No formal RIM program',
      'Cloud-based records with no retention controls',
      'Destruction during litigation holds not implemented',
    ],
    penalties: 'Criminal penalties: Up to 20 years imprisonment for destruction of documents.',
    remediationSteps: [
      'Implement 7-year retention policy for all audit/financial records',
      'Disable auto-delete on relevant record categories',
      'Implement legal hold process',
      'Ensure cloud backups have matching retention periods',
    ],
    applicableTo: ['Public companies', 'Audit firms serving public companies'],
  },
];

// ─── PCI-DSS (Payment Card Industry Data Security Standard) ───────
const PCI_CHECKS: ComplianceCheck[] = [
  {
    id: 'pci-firewall-config',
    regulation: 'PCI-DSS',
    section: '1',
    title: 'Network Security Controls (Firewall/Router)',
    description: 'Protect cardholder data using secure network controls including firewalls and router configurations.',
    severity: 'critical',
    category: 'Network Security',
    requirements: [
      'Install and maintain network security controls (firewalls)',
      'Restrict inbound/outbound network traffic to cardholder data environment only',
      'Prohibit direct public access between internet and cardholder data environment',
      'Review rule sets every 6 months',
    ],
    commonViolations: [
      'Default firewall rules allow all traffic',
      'No network segmentation between CDE and general network',
      'Outdated router configurations',
      'No firewall rule review documentation',
    ],
    penalties: '$5,000-$100,000 per month by card brands; potential loss of card processing rights.',
    remediationSteps: [
      'Implement dedicated firewall for cardholder data environment',
      'Segment CDE from general corporate network',
      'Deny-all inbound traffic with explicit allow rules only',
      'Schedule semi-annual firewall rule reviews',
    ],
    applicableTo: ['Any organization that stores, processes, or transmits credit card data'],
  },
  {
    id: 'pci-default-passwords',
    regulation: 'PCI-DSS',
    section: '2',
    title: 'Default Credential Management',
    description: 'Change all vendor-default passwords and remove/generic accounts before systems enter production.',
    severity: 'critical',
    category: 'Credential Security',
    requirements: [
      'Change all vendor-supplied defaults (passwords, SNMP strings)',
      'Remove or disable default accounts',
      'Shared accounts/groups not allowed unless explicitly authorized',
      'Encrypt all non-console administrative access',
    ],
    commonViolations: [
      'Default passwords on databases/firewalls/routers',
      'Default admin accounts left active and unmodified',
      'SNMP community strings set to default "public"/"private"',
      'VPN default configurations not customized',
    ],
    penalties: 'Same as PCI Req 1; immediate failure of assessment if present.',
    remediationSteps: [
      'Inventory all systems and identify vendor defaults',
      'Change all default passwords and SNMP strings',
      'Remove or disable all default/generic accounts',
      'Implement MFA for all non-console admin access',
    ],
    applicableTo: ['All systems in cardholder data environment'],
  },
  {
    id: 'pci-data-encryption',
    regulation: 'PCI-DSS',
    section: '3',
    title: 'Protect Stored Cardholder Data',
    description: 'Protect stored cardholder data with strong encryption, masking, and access controls.',
    severity: 'critical',
    category: 'Data Protection',
    requirements: [
      'Encrypt stored cardholder data with AES-256',
      'PAN must be rendered unreadable (encryption, truncation, hashing, tokenization)',
      'Never store full magnetic stripe, CVV, or PIN after authorization',
      'Cryptographic keys managed separately from encrypted data',
    ],
    commonViolations: [
      'Storing full track data or CVVs',
      'No encryption for stored card numbers in database',
      'Plaintext PANs visible in analytics or logs',
      'Encryption keys stored in same database as card data',
    ],
    penalties: 'Card brand fines; forensic investigation costs; potential loss of card processing privileges.',
    remediationSteps: [
      'Implement AES-256 encryption for all stored PANs',
      'Tokenize card data to eliminate plaintext storage',
      'Purge all CVV, track data, and PIN data post-authorization',
      'Implement proper key management procedures (HSM recommended)',
    ],
    applicableTo: ['All organizations with stored cardholder data'],
  },
];

// ─── CCPA (California Consumer Privacy Act) ────────────────────────
const CCPA_CHECKS: ComplianceCheck[] = [
  {
    id: 'ccpa-privacy-rights',
    regulation: 'CCPA',
    section: '1798.100',
    title: 'Consumer Right to Know & Delete',
    description: 'Consumers have the right to know what personal information is collected and request deletion.',
    severity: 'critical',
    category: 'Consumer Rights',
    requirements: [
      'Respond to verifiable access requests within 45 days',
      'Provide categories and specific pieces of information collected',
      'Honor deletion requests within 45 days',
      'Do not discriminate against consumers exercising rights',
    ],
    commonViolations: [
      'No mechanism for consumers to submit requests',
      'Privacy policy does not describe data categories collected',
      'Failed to respond within 45-day deadline',
      'Charging fees for access requests',
    ],
    penalties: 'Statutory damages $100-$750 per consumer per incident or actual damages, whichever is greater.',
    remediationSteps: [
      'Implement consumer request portal or designate email/phone channel',
      'Document all data categories collected and shared',
      'Build automated request tracking and response workflow',
      'Train customer service on CCPA verification procedures',
    ],
    applicableTo: ['Businesses serving CA residents with $25M+ revenue or 100K+ consumers or derives 50%+ revenue from selling PI'],
  },
  {
    id: 'ccpa-opt-out-sale',
    regulation: 'CCPA',
    section: '1798.120',
    title: 'Right to Opt-Out of Sale',
    description: 'Businesses that sell personal information must provide a clear opt-out mechanism.',
    severity: 'high',
    category: 'Consumer Rights',
    requirements: [
      'Post "Do Not Sell My Personal Information" link conspicuously',
      'Honor opt-out requests within 15 business days',
      'Do not require consumers to create accounts to opt-out',
      'Wait 12 months before asking opted-out consumers to re-consent',
    ],
    commonViolations: [
      'No "Do Not Sell" link on homepage',
      'Requiring account creation for opt-out',
      'Slow response to opt-out requests',
      'Not honoring opt-out signals (GPC)',
    ],
    penalties: 'Civil penalties up to $7,500 per violation from AG.',
    remediationSteps: [
      'Add "Do Not Sell My Personal Information" link to website footer',
      'Support Global Privacy Control (GPC) browser signals',
      'Automate opt-out processing within 15 business days',
      'Implement cookie consent management that respects opt-outs',
    ],
    applicableTo: ['Businesses that sell personal information of CA residents'],
  },
  {
    id: 'ccpa-data-minimization',
    regulation: 'CCPA',
    section: '1798.100(c)',
    title: 'Data Minimization',
    description: 'Businesses should collect, use, and retain only what is reasonably necessary.',
    severity: 'medium',
    category: 'Data Governance',
    requirements: [
      'Collect only information reasonably necessary for disclosed purpose',
      'Do not use personal information for undisclosed purposes',
      'Limit internal access to those with legitimate business purpose',
      'Implement retention schedules based on purpose',
    ],
    commonViolations: [
      'Collecting excessive personal information "just in case"',
      'No retention/destruction schedules',
      'Broad internal access to personal data',
      'Re-purposing data without notice or consent',
    ],
    penalties: 'Civil penalties up to $7,500 per violation.',
    remediationSteps: [
      'Conduct data minimization audit of all collected information',
      'Remove unnecessary data collection points',
      'Implement retention schedules with automated deletion',
      'Restrict data access on need-to-know basis',
    ],
    applicableTo: ['All CCPA-covered businesses'],
  },
];

// ─── HIPAA (Health Insurance Portability and Accountability Act) ───
const HIPAA_CHECKS: ComplianceCheck[] = [
  {
    id: 'hipaa-privacy-rule',
    regulation: 'HIPAA',
    section: 'Privacy Rule — 45 CFR Part 160 & 164',
    title: 'Protected Health Information (PHI) Privacy Safeguards',
    description: 'Covered entities must implement safeguards to protect individually identifiable health information.',
    severity: 'critical',
    category: 'Privacy & Security',
    requirements: [
      'Designate a Privacy Officer',
      'Train all workforce members on privacy policies',
      'Implement access controls for PHI',
      'Maintain privacy policies and procedures',
      'Obtain patient authorization for non-TPO uses',
    ],
    commonViolations: [
      'No designated Privacy Officer',
      'Staff not trained on HIPAA requirements',
      'No access controls on systems containing PHI',
      'PHI visible to unauthorized personnel',
    ],
    penalties: 'Civil penalties: $100-$50,000 per violation; annual max $1.5M per violation tier. Criminal penalties up to $250K and 10 years imprisonment.',
    remediationSteps: [
      'Designate HIPAA Privacy Officer and Security Officer',
      'Conduct organization-wide HIPAA training',
      'Implement role-based access for PHI-containing systems',
      'Draft and publish privacy policies and procedures',
    ],
    applicableTo: ['Healthcare providers', 'Health plans', 'Healthcare clearinghouses', 'Business associates'],
  },
  {
    id: 'hipaa-security-rule',
    regulation: 'HIPAA',
    section: 'Security Rule — 45 CFR 164.302',
    title: 'Administrative, Physical & Technical Safeguards',
    description: 'Covered entities must implement appropriate administrative, physical, and technical safeguards for electronic PHI.',
    severity: 'critical',
    category: 'Security Controls',
    requirements: [
      'Conduct annual risk assessment',
      'Implement access controls (unique user IDs, automatic logoff)',
      'Encrypt ePHI at rest and in transit',
      'Maintain audit logs of systems accessing ePHI',
      'Develop and test contingency plans',
    ],
    commonViolations: [
      'No annual risk assessment',
      'Shared credentials for accessing ePHI systems',
      'No encryption on laptops/devices with ePHI',
      'No audit trail for PHI access',
    ],
    penalties: 'Same tier structure as Privacy Rule.',
    remediationSteps: [
      'Perform formal HIPAA risk assessment',
      'Implement MFA for all ePHI access',
      'Encrypt all ePHI at rest (AES-256) and in transit (TLS 1.2+)',
      'Deploy audit logging for ePHI systems',
    ],
    applicableTo: ['All covered entities and business associates handling ePHI'],
  },
  {
    id: 'hipaa-breach-notification',
    regulation: 'HIPAA',
    section: '45 CFR 164.404',
    title: 'Breach Notification Rule',
    description: 'Covered entities must notify affected individuals, HHS, and media (for large breaches) of unsecured PHI breaches.',
    severity: 'high',
    category: 'Incident Response',
    requirements: [
      'Notify affected individuals within 60 days of discovery',
      'Notify HHS within 60 days (if >500 individuals, immediately)',
      'Notify prominent media outlets if >500 individuals affected in a state',
      'Maintain breach log and report annually',
    ],
    commonViolations: [
      'No incident response plan',
      'Delayed notification beyond 60-day requirement',
      'No breach risk assessment methodology',
      'No documentation of breach analysis',
    ],
    penalties: 'Failure to notify can result in (willful neglect) penalties ($50,000 per violation).',
    remediationSteps: [
      'Develop formal incident response plan with breach notification procedures',
      'Implement automated breach detection (DLP, EDR)',
      'Pre-draft notification templates for 60-day window',
      'Conduct annual tabletop exercise for breach scenarios',
    ],
    applicableTo: ['All covered entities and business associates'],
  },
];

export const ALL_CHECKS: ComplianceCheck[] = [
  ...GLBA_CHECKS,
  ...SOX_CHECKS,
  ...PCI_CHECKS,
  ...CCPA_CHECKS,
  ...HIPAA_CHECKS,
];
