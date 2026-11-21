/**
 * ExtSentinel - Browser Extension Security Scanner
 * Type definitions for detection engine and UI
 */

// Extension risk assessment types
export interface ExtensionRisk {
  id: string;
  name: string;
  version: string;
  description: string;
  publisher?: string;
  permissions: string[];
  hostPermissions: string[];
  iconUrl?: string;
  installType: string;
  enabled: boolean;
  homepageUrl?: string;
  updateUrl?: string;
  riskScore: number;
  riskLevel: RiskLevel;
  findings: SecurityFinding[];
  installDate?: number;
}

export type RiskLevel = 'critical' | 'high' | 'medium' | 'low' | 'safe';

export interface SecurityFinding {
  id: string;
  category: FindingCategory;
  severity: RiskLevel;
  title: string;
  description: string;
  recommendation: string;
  techniqueId?: string; // Maps to BET technique IDs
  evidence?: string;
}

export type FindingCategory =
  | 'permissions'
  | 'host_access'
  | 'code_analysis'
  | 'publisher'
  | 'network'
  | 'behavior'
  | 'update_channel';

// Detection rule types
export interface DetectionRule {
  id: string;
  name: string;
  description: string;
  category: FindingCategory;
  severity: RiskLevel;
  techniqueId: string;
  check: (ext: chrome.management.ExtensionInfo) => RuleResult | null;
}

export interface RuleResult {
  triggered: boolean;
  title: string;
  description: string;
  recommendation: string;
  evidence?: string;
}

// DOM monitoring types
export interface DOMIntegrityAlert {
  id: string;
  timestamp: number;
  url: string;
  type: 'form_tampering' | 'overlay_injection' | 'script_injection' | 'redirect_hijack' | 'credential_harvesting';
  severity: RiskLevel;
  description: string;
  element?: string;
}

// Background scan results
export interface ScanResult {
  timestamp: number;
  totalExtensions: number;
  extensionsScanned: number;
  criticalCount: number;
  highCount: number;
  mediumCount: number;
  lowCount: number;
  safeCount: number;
  extensions: ExtensionRisk[];
  alerts: SecurityAlert[];
}

export interface SecurityAlert {
  id: string;
  timestamp: number;
  severity: RiskLevel;
  title: string;
  message: string;
  extensionName?: string;
  techniqueId?: string;
}

// Settings
export interface ExtSentinelSettings {
  autoScanEnabled: boolean;
  autoScanInterval: number; // hours
  domProtectionEnabled: boolean;
  credentialProtectionEnabled: boolean;
  showNotifications: boolean;
  ignoredExtensions: string[];
  sensitivityLevel: 'strict' | 'balanced' | 'permissive';
  scanOnInstall: boolean;
  blockHighRiskExtensions: boolean;
}

export const DEFAULT_SETTINGS: ExtSentinelSettings = {
  autoScanEnabled: true,
  autoScanInterval: 24,
  domProtectionEnabled: true,
  credentialProtectionEnabled: true,
  showNotifications: true,
  ignoredExtensions: [],
  sensitivityLevel: 'balanced',
  scanOnInstall: true,
  blockHighRiskExtensions: false,
};

// Permission risk database
export const PERMISSION_RISKS: Record<string, { risk: number; reason: string }> = {
  'management': { risk: 90, reason: 'Can manage other extensions - high abuse potential for disabling security tools' },
  'tabs': { risk: 60, reason: 'Can access all tab content and URLs - potential data harvesting' },
  'activeTab': { risk: 20, reason: 'Limited to current active tab - lower risk' },
  'scripting': { risk: 80, reason: 'Can inject scripts into any page - content manipulation capability' },
  'webRequest': { risk: 85, reason: 'Can intercept and modify all network traffic' },
  'webRequestBlocking': { risk: 95, reason: 'Can block and modify network requests in real-time' },
  'cookies': { risk: 75, reason: 'Can access all cookies including session tokens' },
  'storage': { risk: 30, reason: 'Can store data locally - moderate risk for data caching' },
  'unlimitedStorage': { risk: 40, reason: 'Unlimited local storage - potential for large-scale data collection' },
  'downloads': { risk: 50, reason: 'Can initiate downloads - potential malware delivery vector' },
  'history': { risk: 65, reason: 'Full browsing history access - privacy violation' },
  'bookmarks': { risk: 35, reason: 'Can read and modify bookmarks' },
  'clipboardRead': { risk: 85, reason: 'Can read clipboard contents - credential theft vector' },
  'clipboardWrite': { risk: 40, reason: 'Can modify clipboard contents' },
  'desktopCapture': { risk: 90, reason: 'Can capture screen content - sensitive data exposure' },
  'pageCapture': { risk: 70, reason: 'Can capture page screenshots' },
  'proxy': { risk: 95, reason: 'Can control browser proxy settings - full traffic interception' },
  'nativeMessaging': { risk: 90, reason: 'Can communicate with native OS applications' },
  'debugger': { risk: 100, reason: 'Full browser debugger access - complete control' },
  'processes': { risk: 80, reason: 'Can access browser process information' },
  'system.cpu': { risk: 50, reason: 'System CPU information access' },
  'system.memory': { risk: 50, reason: 'System memory information access' },
  'system.storage': { risk: 60, reason: 'System storage information access' },
  'system.display': { risk: 40, reason: 'Display information access' },
  'privacy': { risk: 70, reason: 'Can modify privacy-related browser settings' },
  'browsingData': { risk: 60, reason: 'Can clear browsing data - evidence destruction' },
  'contentSettings': { risk: 55, reason: 'Can modify content settings per site' },
  'contextMenus': { risk: 25, reason: 'Can add context menu items - low direct risk' },
  'notifications': { risk: 20, reason: 'Can display notifications - social engineering vector' },
  'geolocation': { risk: 45, reason: 'Can access user geolocation' },
  'identity': { risk: 70, reason: 'Can access OAuth2 tokens' },
  'idle': { risk: 20, reason: 'Can detect user idle state' },
  'tts': { risk: 10, reason: 'Text-to-speech access' },
  'ttsEngine': { risk: 15, reason: 'Can provide text-to-speech engine' },
  'fileSystem': { risk: 75, reason: 'Can access local file system' },
  'fileSystemProvider': { risk: 70, reason: 'Can provide file system access' },
  'certificateProvider': { risk: 85, reason: 'Can provide client certificates' },
  'platformKeys': { risk: 90, reason: 'Access to platform key store' },
};

// Suspicious host permission patterns
export const SUSPICIOUS_HOST_PATTERNS = [
  { pattern: '<all_urls>', risk: 80, reason: 'Access to ALL websites - maximum attack surface' },
  { pattern: '*://*/*', risk: 75, reason: 'Wildcard access to all HTTP/HTTPS sites' },
  { pattern: 'file:///*', risk: 70, reason: 'Access to local files - data exfiltration risk' },
  { pattern: '*://*.google.com/*', risk: 40, reason: 'Targeting Google services' },
  { pattern: '*://*.facebook.com/*', risk: 40, reason: 'Targeting Facebook' },
  { pattern: '*://*.github.com/*', risk: 45, reason: 'Targeting GitHub - developer credential theft' },
  { pattern: '*://*.amazon.com/*', risk: 40, reason: 'Targeting Amazon - financial fraud' },
  { pattern: '*://*.paypal.com/*', risk: 50, reason: 'Targeting PayPal - direct financial theft' },
  { pattern: '*://*.bank*', risk: 55, reason: 'Targeting banking sites' },
  { pattern: '*://*wallet*', risk: 50, reason: 'Targeting cryptocurrency wallets' },
  { pattern: '*://*crypto*', risk: 50, reason: 'Targeting cryptocurrency services' },
  { pattern: '*://*exchange*', risk: 45, reason: 'Targeting crypto exchanges' },
];

// Known malicious indicators
export const MALICIOUS_INDICATORS = {
  suspiciousPermissions: [
    'debugger',
    'proxy',
    'nativeMessaging',
    'clipboardRead',
    'desktopCapture',
    'pageCapture',
  ],
  highRiskPermissionCombos: [
    ['tabs', 'scripting', 'cookies'],
    ['webRequest', 'webRequestBlocking', 'storage'],
    ['management', 'scripting'],
    ['clipboardRead', 'tabs', 'storage'],
  ],
  suspiciousNamePatterns: [
    /meta.{0,2}mask/i,
    /wallet.{0,3}(pro|plus|premium)/i,
    /vpn.{0,3}(free|unlimited|premium)/i,
    /ad.{0,2}block.{0,3}(pro|plus)/i,
    /password.{0,3}(recovery|stealer|dump)/i,
    /crypto.{0,3}(miner|bot)/i,
  ],
};
