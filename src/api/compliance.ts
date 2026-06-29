import { ComplianceCheck, ComplianceRequest, ComplianceReport, ALL_CHECKS } from '../data/compliance-checks';

export function analyzeCompliance(request: ComplianceRequest): ComplianceReport {
  const findings: ComplianceReport['findings'] = [];
  
  const industry = request.industry?.toLowerCase() || '';
  const dataType = (request.dataType || '').toLowerCase() || '';
  const practices = request.practices?.map((p: string) => p.toLowerCase()) || [];
  const dataTypes = request.dataTypes?.map((d: string) => d.toLowerCase()) || [];
  
  // Filter which checks apply
  const applicableChecks = ALL_CHECKS.filter(check => {
    // Industry filtering
    if (industry.includes('health') || industry.includes('medical') || industry.includes('hospital')) {
      if (check.regulation === 'HIPAA') return true;
    }
    if (industry.includes('bank') || industry.includes('finance') || industry.includes('credit') || industry.includes('loan') || industry.includes('mortgage')) {
      if (check.regulation === 'GLBA') return true;
    }
    if (industry.includes('public') || industry.includes('listed') || industry.includes('corporation')) {
      if (check.regulation === 'SOX') return true;
    }
    if (dataType.includes('credit card') || dataTypes.includes('payment') || practices.includes('processes credit cards')) {
      if (check.regulation === 'PCI-DSS') return true;
    }
    // CCPA applies broadly if CA consumers or thresholds met
    if (request.state === 'CA' || industry.includes('retail') || industry.includes('tech') || industry.includes('saas') || industry.includes('advertising')) {
      if (check.regulation === 'CCPA') return true;
    }
    return false;
  });
  
  // If no specific industry filter ran, include all checks for a general audit
  const checksToCheck = applicableChecks.length > 0 ? applicableChecks : ALL_CHECKS.slice(0, 8);
  
  for (const check of checksToCheck) {
    let status: 'pass' | 'fail' | 'warning' = 'pass';
    let notes = '';
    
    // Pattern-based analysis
    const violationPatterns = check.commonViolations.map((v: string) => v.toLowerCase());
    const practiceMatch = practices.some((p: string) =>
      violationPatterns.some((v: string) => v.includes(p) || p.includes(v))
    );
    
    if (practiceMatch) {
      status = 'fail';
      notes = 'Practice matches known violation pattern.';
    } else if (request.website) {
      // Check for missing patterns that should trigger warnings
      if (check.id.includes('privacy-notice') && !request.practices?.includes('privacy notice')) {
        status = 'warning';
        notes = 'Privacy notice not declared; likely missing or unverified.';
      } else if (check.id.includes('firewall') && !dataTypes.includes('cardholder')) {
        status = 'warning';
        notes = 'Firewall configuration not confirmed; requires technical assessment.';
      }
    }
    
    // Hard-fail triggers based on explicit practices
    if (practices.includes('stores cvv') && check.id === 'pci-data-encryption') {
      status = 'fail';
      notes = 'CVV storage is prohibited under PCI-DSS regardless of encryption.';
    }
    if (practices.includes('default passwords') && check.id === 'pci-default-passwords') {
      status = 'fail';
      notes = 'Default credentials are a critical PCI failure.';
    }
    if (practices.includes('sell customer data') && check.id === 'glba-privacy-notice') {
      status = 'fail';
      notes = 'Selling customer data requires explicit privacy notice and opt-out.';
    }
    
    findings.push({ check, status, notes });
  }
  
  const passed = findings.filter(f => f.status === 'pass').length;
  const failed = findings.filter((f: typeof findings[number]) => f.status === 'fail').length;
  const warnings = findings.filter((f: typeof findings[number]) => f.status === 'warning').length;
  
  const total = findings.length;
  const baseScore = total > 0 ? Math.round((passed / total) * 100) : 100;
  const score = Math.max(0, baseScore - failed * 15);
  
  const failedChecks = findings.filter(f => f.status === 'fail').map(f => f.check.title);
  
  const executiveSummary = failed > 3
    ? `CRITICAL: ${failed} compliance failures across ${total} checks. Immediate remediation required.`
    : failed > 0
    ? `WARNING: ${failed} compliance issue(s) found. Address within 30 days to maintain compliance.`
    : `COMPLIANT: ${passed}/${total} checks passed. Continue monitoring and maintain controls.`;
  
  const nextSteps = failedChecks.length > 0
    ? [
        `Immediately address: ${failedChecks.slice(0, 3).join(', ')}`,
        'Engage compliance counsel for remediation planning',
        'Document remediation plan with owner and deadlines',
        'Schedule follow-up audit in 90 days',
      ]
    : [
        'Continue annual compliance training',
        'Update risk assessment for any changes',
        'Review incident response procedures quarterly',
        'Audit third-party vendor compliance annually',
      ];
  
  return {
    totalChecks: total,
    passed,
    failed,
    warnings,
    riskScore: score,
    findings,
    executiveSummary,
    nextSteps,
  };
}
