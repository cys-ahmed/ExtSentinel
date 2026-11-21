/**
 * ExtSentinel Storage Utilities
 * Chrome storage API wrapper for settings and scan results
 */

import { type ExtSentinelSettings, type ScanResult, DEFAULT_SETTINGS } from '@/types'

const STORAGE_KEYS = {
  settings: 'extsentinel_settings',
  lastScan: 'extsentinel_last_scan',
  alerts: 'extsentinel_alerts',
  scanHistory: 'extsentinel_scan_history',
} as const

/**
 * Get settings from Chrome storage
 */
export async function getSettings(): Promise<ExtSentinelSettings> {
  try {
    const result = await chrome.storage.local.get(STORAGE_KEYS.settings)
    const stored = result[STORAGE_KEYS.settings] as ExtSentinelSettings | undefined
    return stored ? { ...DEFAULT_SETTINGS, ...stored } : DEFAULT_SETTINGS
  } catch {
    return DEFAULT_SETTINGS
  }
}

/**
 * Save settings to Chrome storage
 */
export async function saveSettings(settings: ExtSentinelSettings): Promise<void> {
  await chrome.storage.local.set({ [STORAGE_KEYS.settings]: settings })
}

/**
 * Get last scan result
 */
export async function getLastScan(): Promise<ScanResult | null> {
  try {
    const result = await chrome.storage.local.get(STORAGE_KEYS.lastScan)
    const stored = result[STORAGE_KEYS.lastScan] as ScanResult | undefined
    return stored || null
  } catch {
    return null
  }
}

/**
 * Save scan result
 */
export async function saveScanResult(scan: ScanResult): Promise<void> {
  await chrome.storage.local.set({ [STORAGE_KEYS.lastScan]: scan })

  // Also add to history
  const history = await getScanHistory()
  history.unshift(scan)
  // Keep last 50 scans
  if (history.length > 50) history.length = 50
  await chrome.storage.local.set({ [STORAGE_KEYS.scanHistory]: history })
}

/**
 * Get scan history
 */
export async function getScanHistory(): Promise<ScanResult[]> {
  try {
    const result = await chrome.storage.local.get(STORAGE_KEYS.scanHistory)
    const stored = result[STORAGE_KEYS.scanHistory] as ScanResult[] | undefined
    return stored || []
  } catch {
    return []
  }
}

/**
 * Add a security alert
 */
export async function addAlert(alert: {
  severity: string
  title: string
  message: string
  extensionName?: string
  techniqueId?: string
}): Promise<void> {
  const alerts = await getAlerts()
  alerts.unshift({
    id: `alert-${Date.now()}-${Math.random().toString(36).substr(2, 9)}`,
    timestamp: Date.now(),
    ...alert,
  })
  // Keep last 100 alerts
  if (alerts.length > 100) alerts.length = 100
  await chrome.storage.local.set({ [STORAGE_KEYS.alerts]: alerts })
}

/**
 * Get all alerts
 */
export async function getAlerts(): Promise<Array<{
  id: string
  timestamp: number
  severity: string
  title: string
  message: string
  extensionName?: string
  techniqueId?: string
}>> {
  try {
    const result = await chrome.storage.local.get(STORAGE_KEYS.alerts)
    const stored = result[STORAGE_KEYS.alerts] as Array<{
      id: string
      timestamp: number
      severity: string
      title: string
      message: string
      extensionName?: string
      techniqueId?: string
    }> | undefined
    return stored || []
  } catch {
    return []
  }
}

/**
 * Clear all alerts
 */
export async function clearAlerts(): Promise<void> {
  await chrome.storage.local.remove(STORAGE_KEYS.alerts)
}

/**
 * Check if auto-scan is due
 */
export async function isAutoScanDue(): Promise<boolean> {
  const settings = await getSettings()
  if (!settings.autoScanEnabled) return false

  const lastScan = await getLastScan()
  if (!lastScan) return true

  const intervalMs = settings.autoScanInterval * 60 * 60 * 1000
  return Date.now() - lastScan.timestamp > intervalMs
}
