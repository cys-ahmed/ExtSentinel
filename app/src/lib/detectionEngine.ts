/**
 * ExtSentinel Detection Engine
 * Core security analysis logic for browser extension risk assessment
 * Implements detection rules mapped from the phishing extension research
 */

import {
  type ExtensionRisk,
  type SecurityFinding,
  type RiskLevel,
  PERMISSION_RISKS,
  SUSPICIOUS_HOST_PATTERNS,
  MALICIOUS_INDICATORS,
} from '@/types'

/**
 * Calculate risk score and generate findings for an extension
 */
export async function analyzeExtension(
  ext: chrome.management.ExtensionInfo
): Promise<ExtensionRisk> {
  const findings: SecurityFinding[] = []
  let totalRiskScore = 0
  let maxPossibleScore = 0

  // Permission analysis
  const permissionFindings = analyzePermissions(ext)
  findings.push(...permissionFindings)
  totalRiskScore += permissionFindings.reduce((sum, f) => sum + severityToScore(f.severity), 0)
  maxPossibleScore += 50

  // Host permission analysis
  const hostFindings = analyzeHostPermissions(ext)
  findings.push(...hostFindings)
  totalRiskScore += hostFindings.reduce((sum, f) => sum + severityToScore(f.severity), 0)
  maxPossibleScore += 30

  // Publisher & metadata analysis
  const publisherFindings = analyzePublisher(ext)
  findings.push(...publisherFindings)
  totalRiskScore += publisherFindings.reduce((sum, f) => sum + severityToScore(f.severity), 0)
  maxPossibleScore += 20

  // Code/install behavior analysis
  const behaviorFindings = analyzeBehavior(ext)
  findings.push(...behaviorFindings)
  totalRiskScore += behaviorFindings.reduce((sum, f) => sum + severityToScore(f.severity), 0)
  maxPossibleScore += 25

  // Permission combination analysis
  const comboFindings = analyzePermissionCombinations(ext)
  findings.push(...comboFindings)
  totalRiskScore += comboFindings.reduce((sum, f) => sum + severityToScore(f.severity), 0)
  maxPossibleScore += 35

  // Calculate normalized risk score (0-100)
  const normalizedScore = Math.min(100, Math.round((totalRiskScore / Math.max(maxPossibleScore, 1)) * 100))

  return {
    id: ext.id,
    name: ext.name,
    version: ext.version,
    description: ext.description || 'No description provided',
    publisher: ext.hostPermissions?.[0] || undefined,
    permissions: ext.permissions || [],
    hostPermissions: ext.hostPermissions || [],
    iconUrl: ext.icons && ext.icons.length > 0
      ? ext.icons[ext.icons.length - 1].url
      : undefined,
    installType: ext.installType,
    enabled: ext.enabled,
    homepageUrl: ext.homepageUrl,
    updateUrl: ext.updateUrl,
    riskScore: normalizedScore,
    riskLevel: scoreToRiskLevel(normalizedScore),
    findings,
    installDate: ext.installType === 'development'
      ? undefined
      : Date.now() - Math.random() * 30 * 24 * 60 * 60 * 1000, // Approximate for demo
  }
}

/**
 * Analyze individual permissions for risk
 */
function analyzePermissions(ext: chrome.management.ExtensionInfo): SecurityFinding[] {
  const findings: SecurityFinding[] = []
  const permissions = ext.permissions || []

  for (const perm of permissions) {
    const risk = PERMISSION_RISKS[perm]
    if (risk && risk.risk >= 70) {
      findings.push({
        id: `perm-${perm}`,
        category: 'permissions',
        severity: risk.risk >= 90 ? 'critical' : risk.risk >= 70 ? 'high' : 'medium',
        title: `High-Risk Permission: ${perm}`,
        description: risk.reason,
        recommendation: `Review if ${perm} is essential for this extension's functionality. Consider alternatives that don't require this permission.`,
        techniqueId: perm === 'clipboardRead'
          ? 'BET.TA0006.004'
          : perm === 'scripting'
            ? 'BET.TA0002.001'
            : perm === 'cookies'
              ? 'BET.TA0006.002'
              : 'BET.TA0004.002',
        evidence: `Permission "${perm}" declared in manifest`,
      })
    }
  }

  // Check for debugger permission (absolute highest risk)
  if (permissions.includes('debugger')) {
    findings.push({
      id: 'perm-debugger',
      category: 'permissions',
      severity: 'critical',
      title: 'CRITICAL: Debugger Permission Detected',
      description: 'This extension has full debugger access, effectively giving it complete control over the browser. This permission is rarely legitimate for consumer extensions.',
      recommendation: 'Remove this extension immediately unless it is a verified development tool from a trusted publisher.',
      techniqueId: 'BET.TA0004.002',
      evidence: 'debugger permission present',
    })
  }

  // Check for proxy permission
  if (permissions.includes('proxy')) {
    findings.push({
      id: 'perm-proxy',
      category: 'permissions',
      severity: 'critical',
      title: 'CRITICAL: Proxy Control Permission',
      description: 'This extension can control browser proxy settings, enabling full traffic interception and man-in-the-middle attacks.',
      recommendation: 'Verify this is a legitimate VPN/proxy extension from a verified publisher. Remove if unnecessary.',
      techniqueId: 'BET.TA0011.001',
      evidence: 'proxy permission present',
    })
  }

  return findings
}

/**
 * Analyze host permissions for risk
 */
function analyzeHostPermissions(ext: chrome.management.ExtensionInfo): SecurityFinding[] {
  const findings: SecurityFinding[] = []
  const hostPerms = ext.hostPermissions || []

  for (const hostPerm of hostPerms) {
    for (const suspicious of SUSPICIOUS_HOST_PATTERNS) {
      const regex = new RegExp(
        suspicious.pattern.replace(/\*/g, '.*').replace(/\./g, '\\.')
      )
      if (regex.test(hostPerm) || hostPerm === suspicious.pattern) {
        findings.push({
          id: `host-${suspicious.pattern}`,
          category: 'host_access',
          severity: suspicious.risk >= 70 ? 'high' : 'medium',
          title: `Broad Host Access: ${suspicious.pattern}`,
          description: suspicious.reason,
          recommendation: 'Restrict host permissions to only domains essential for the extension\'s functionality.',
          techniqueId: 'BET.TA0002.001',
          evidence: `Host permission: "${hostPerm}"`,
        })
        break
      }
    }
  }

  // Check for all_urls (maximum risk)
  if (hostPerms.includes('<all_urls>')) {
    findings.push({
      id: 'host-all-urls',
      category: 'host_access',
      severity: 'critical',
      title: 'CRITICAL: Access to All Websites (<all_urls>)',
      description: 'This extension can access and modify ANY website you visit. This is the highest possible host permission risk and is a common indicator of malicious extensions seeking to harvest credentials across multiple sites.',
      recommendation: 'Unless this is a reputable password manager, ad blocker, or security tool from a verified publisher, remove this extension immediately.',
      techniqueId: 'BET.TA0002.001',
      evidence: '<all_urls> in host_permissions',
    })
  }

  return findings
}

/**
 * Analyze publisher information and metadata
 */
function analyzePublisher(ext: chrome.management.ExtensionInfo): SecurityFinding[] {
  const findings: SecurityFinding[] = []

  // Check for missing or suspicious publisher info
  if (!ext.homepageUrl && ext.installType !== 'development') {
    findings.push({
      id: 'publisher-missing-homepage',
      category: 'publisher',
      severity: 'medium',
      title: 'No Homepage URL',
      description: 'This extension does not provide a homepage URL, making it difficult to verify the publisher\'s legitimacy.',
      recommendation: 'Research the extension publisher before trusting this extension with sensitive data.',
      techniqueId: 'BET.TA0001.003',
    })
  }

  // Check for suspicious name patterns
  for (const pattern of MALICIOUS_INDICATORS.suspiciousNamePatterns) {
    if (pattern.test(ext.name)) {
      findings.push({
        id: 'publisher-suspicious-name',
        category: 'publisher',
        severity: 'high',
        title: 'Suspicious Extension Name Pattern',
        description: `The extension name "${ext.name}" matches patterns commonly used by impersonating or fraudulent extensions.`,
        recommendation: 'Verify this is the official extension from the brand\'s verified publisher. Check the Chrome Web Store for the authentic version.',
        techniqueId: 'BET.TA0001.003',
        evidence: `Name matches pattern: ${pattern.toString()}`,
      })
      break
    }
  }

  // Check install type
  if (ext.installType === 'sideload') {
    findings.push({
      id: 'publisher-sideloaded',
      category: 'publisher',
      severity: 'high',
      title: 'Sideloaded Extension Detected',
      description: 'This extension was installed outside the official Chrome Web Store, bypassing Google\'s security review process.',
      recommendation: 'Remove sideloaded extensions unless they are enterprise-deployed tools verified by your IT department.',
      techniqueId: 'BET.TA0001.004',
    })
  }

  // Check for external update URL
  if (ext.updateUrl && !ext.updateUrl.includes('google')) {
    findings.push({
      id: 'update-external',
      category: 'update_channel',
      severity: 'medium',
      title: 'External Update Channel',
      description: `This extension uses an external update server (${ext.updateUrl}), which could be used to deliver malicious updates outside of Google's review process.`,
      recommendation: 'Verify the update URL belongs to the legitimate publisher. External update channels are sometimes used for delayed payload delivery.',
      techniqueId: 'BET.TA0003.001',
      evidence: `Update URL: ${ext.updateUrl}`,
    })
  }

  return findings
}

/**
 * Analyze extension behavior indicators
 */
function analyzeBehavior(ext: chrome.management.ExtensionInfo): SecurityFinding[] {
  const findings: SecurityFinding[] = []
  const permissions = ext.permissions || []

  // Check for content script capability (scripting + host permissions)
  if (permissions.includes('scripting') && (ext.hostPermissions?.length ?? 0) > 0) {
    const hasBroadAccess = ext.hostPermissions?.some(
      (hp: string) => hp === '<all_urls>' || hp.includes('*://*/*')
    )
    if (hasBroadAccess) {
      findings.push({
        id: 'behavior-content-injection',
        category: 'behavior',
        severity: 'high',
        title: 'Content Injection Capability on All Sites',
        description: 'This extension can inject scripts into any webpage, enabling DOM manipulation, form hijacking, and credential harvesting.',
        recommendation: 'Ensure this extension has a legitimate need for universal script injection. Content blockers and password managers may need this, but most extensions do not.',
        techniqueId: 'BET.TA0002.001',
      })
    }
  }

  // Check for network interception capability
  if (permissions.includes('webRequest') || permissions.includes('webRequestBlocking')) {
    findings.push({
      id: 'behavior-network-intercept',
      category: 'behavior',
      severity: 'high',
      title: 'Network Traffic Interception Capability',
      description: 'This extension can intercept and potentially modify all HTTP/HTTPS requests and responses, including headers containing authentication tokens.',
      recommendation: 'Verify this is a legitimate security, privacy, or debugging tool. Network interception is a powerful capability rarely needed by consumer extensions.',
      techniqueId: 'BET.TA0009.003',
    })
  }

  // Check for native messaging
  if (permissions.includes('nativeMessaging')) {
    findings.push({
      id: 'behavior-native-messaging',
      category: 'behavior',
      severity: 'critical',
      title: 'Native Application Communication',
      description: 'This extension can communicate with applications installed on your computer, potentially bypassing browser sandbox protections.',
      recommendation: 'Only trusted enterprise or security tools should have native messaging access. Remove unless explicitly required.',
      techniqueId: 'BET.TA0002.005',
    })
  }

  return findings
}

/**
 * Analyze dangerous permission combinations
 */
function analyzePermissionCombinations(ext: chrome.management.ExtensionInfo): SecurityFinding[] {
  const findings: SecurityFinding[] = []
  const permissions = ext.permissions || []
  const permSet = new Set(permissions)

  for (const combo of MALICIOUS_INDICATORS.highRiskPermissionCombos) {
    const allPresent = combo.every(p => permSet.has(p))
    if (allPresent) {
      findings.push({
        id: `combo-${combo.join('-')}`,
        category: 'permissions',
        severity: 'critical',
        title: `Dangerous Permission Combination: [${combo.join(', ')}]`,
        description: `This extension has a high-risk combination of permissions that together enable ${getComboDescription(combo)}.`,
        recommendation: 'This permission combination is commonly abused by malicious extensions. Remove unless absolutely necessary and from a fully trusted source.',
        techniqueId: 'BET.TA0004.002',
        evidence: `Permissions present: ${combo.join(', ')}`,
      })
    }
  }

  // Check for data harvesting combination
  if (permSet.has('tabs') && permSet.has('clipboardRead')) {
    findings.push({
      id: 'combo-harvesting',
      category: 'permissions',
      severity: 'high',
      title: 'Data Harvesting Pattern: tabs + clipboardRead',
      description: 'This extension can see what pages you visit AND read your clipboard contents. This combination is used to steal copied passwords and sensitive data.',
      recommendation: 'Verify this extension legitimately needs both page visibility and clipboard access. Consider revoking clipboard permission.',
      techniqueId: 'BET.TA0006.004',
    })
  }

  return findings
}

function getComboDescription(combo: string[]): string {
  const descriptions: Record<string, string> = {
    'tabs-scripting-cookies': 'complete session hijacking by reading cookies from any tab and injecting scripts to steal session data',
    'webRequest-webRequestBlocking-storage': 'silent traffic interception with local data storage for harvested credentials',
    'management-scripting': 'disabling security extensions while injecting malicious scripts',
    'clipboardRead-tabs-storage': 'large-scale credential and data harvesting from clipboard and web pages',
  }
  const key = combo.join('-')
  return descriptions[key] || 'advanced attack scenarios including credential theft and session hijacking'
}

/**
 * Convert risk score (0-100) to risk level
 */
function scoreToRiskLevel(score: number): RiskLevel {
  if (score >= 80) return 'critical'
  if (score >= 60) return 'high'
  if (score >= 40) return 'medium'
  if (score >= 20) return 'low'
  return 'safe'
}

/**
 * Convert severity to numeric score
 */
function severityToScore(severity: RiskLevel): number {
  const scores: Record<RiskLevel, number> = {
    critical: 25,
    high: 15,
    medium: 8,
    low: 3,
    safe: 0,
  }
  return scores[severity] || 0
}

/**
 * Generate a human-readable summary of the scan
 */
export function generateScanSummary(results: ExtensionRisk[]): {
  criticalCount: number
  highCount: number
  mediumCount: number
  lowCount: number
  safeCount: number
  totalRiskScore: number
  highestRiskExtension?: ExtensionRisk
} {
  const criticalCount = results.filter(r => r.riskLevel === 'critical').length
  const highCount = results.filter(r => r.riskLevel === 'high').length
  const mediumCount = results.filter(r => r.riskLevel === 'medium').length
  const lowCount = results.filter(r => r.riskLevel === 'low').length
  const safeCount = results.filter(r => r.riskLevel === 'safe').length
  const totalRiskScore = results.reduce((sum, r) => sum + r.riskScore, 0)
  const highestRiskExtension = results.length > 0
    ? results.reduce((max, r) => r.riskScore > max.riskScore ? r : max)
    : undefined

  return { criticalCount, highCount, mediumCount, lowCount, safeCount, totalRiskScore, highestRiskExtension }
}

/**
 * Check if DOM mutation is suspicious
 */
export function analyzeDOMMutation(
  mutation: MutationRecord,
  _url: string
): { isSuspicious: boolean; reason?: string; severity?: RiskLevel } {
  // Check for password field tampering
  const addedNodes = Array.from(mutation.addedNodes)
  for (const node of addedNodes) {
    if (node instanceof HTMLElement) {
      // Check for invisible overlay elements
      if (isInvisibleOverlay(node)) {
        return {
          isSuspicious: true,
          reason: 'Invisible overlay element detected over page content - potential clickjacking or credential harvesting overlay',
          severity: 'high',
        }
      }

      // Check for form tampering
      if (node.tagName === 'FORM' || node.querySelector('input[type="password"]')) {
        const action = node.getAttribute('action') || (node as HTMLFormElement).action
        if (action && isSuspiciousUrl(action)) {
          return {
            isSuspicious: true,
            reason: `Form submission directed to suspicious URL: ${action}`,
            severity: 'critical',
          }
        }
      }

      // Check for external script injection
      if (node.tagName === 'SCRIPT') {
        const src = (node as HTMLScriptElement).src
        if (src && isSuspiciousUrl(src)) {
          return {
            isSuspicious: true,
            reason: `External script injected from suspicious source: ${src}`,
            severity: 'high',
          }
        }
      }
    }
  }

  // Check for attribute modifications on password fields
  if (mutation.type === 'attributes' && mutation.target instanceof HTMLElement) {
    if (mutation.target.tagName === 'INPUT' &&
        (mutation.target as HTMLInputElement).type === 'password') {
      if (mutation.attributeName === 'formaction' || mutation.attributeName === 'action') {
        return {
          isSuspicious: true,
          reason: 'Password form action modified after page load - potential credential interception',
          severity: 'critical',
        }
      }
    }
  }

  return { isSuspicious: false }
}

/**
 * Check if an element is an invisible overlay
 */
function isInvisibleOverlay(element: HTMLElement): boolean {
  const style = window.getComputedStyle(element)
  const rect = element.getBoundingClientRect()

  // Check for common overlay indicators
  const hasOverlayPosition = style.position === 'fixed' || style.position === 'absolute'
  const isNearFullSize = rect.width > window.innerWidth * 0.8 && rect.height > window.innerHeight * 0.5
  const isLowOpacity = parseFloat(style.opacity) < 0.2
  const isTransparent = style.backgroundColor === 'transparent' || style.backgroundColor === 'rgba(0, 0, 0, 0)'
  const highZIndex = parseInt(style.zIndex) > 1000 || style.zIndex === '9999'

  return hasOverlayPosition && isNearFullSize && (isLowOpacity || isTransparent) && highZIndex
}

/**
 * Check if URL is suspicious
 */
function isSuspiciousUrl(url: string): boolean {
  const suspiciousPatterns = [
    /^(http|https):\/\/[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+/, // IP address
    /\.tk$|\.ml$|\.ga$|\.cf$|\.gq$/, // Free domains commonly abused
    /bit\.ly|tinyurl|t\.co|goo\.gl/, // URL shorteners
    /pastebin|ghostbin|zerobin/, // Paste services
    /telegram\.(me|cc|dog)/, // Telegram (C2 channel)
    /discord\.(com|gg|app)/, // Discord (C2 channel)
  ]
  return suspiciousPatterns.some(p => p.test(url))
}

/**
 * Get color for risk level
 */
export function getRiskColor(level: RiskLevel): string {
  const colors: Record<RiskLevel, string> = {
    critical: '#dc2626',
    high: '#ea580c',
    medium: '#ca8a04',
    low: '#16a34a',
    safe: '#15803d',
  }
  return colors[level]
}

/**
 * Get background color for risk level
 */
export function getRiskBgColor(level: RiskLevel): string {
  const colors: Record<RiskLevel, string> = {
    critical: '#fef2f2',
    high: '#fff7ed',
    medium: '#fefce8',
    low: '#f0fdf4',
    safe: '#f0fdf4',
  }
  return colors[level]
}
