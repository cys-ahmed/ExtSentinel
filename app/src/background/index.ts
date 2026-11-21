/**
 * ExtSentinel Background Service Worker
 * Detection engine that runs in the background to monitor extensions,
 * perform scheduled scans, and alert on suspicious activity.
 */

import { analyzeExtension, generateScanSummary } from '@/lib/detectionEngine'
import {
  getSettings,
  saveScanResult,
  isAutoScanDue,
  addAlert,
  getAlerts,
} from '@/lib/storage'
import type { ScanResult, SecurityAlert, ExtensionRisk } from '@/types'

// Initialize on install
chrome.runtime.onInstalled.addListener(async (details) => {
  console.log('[ExtSentinel] Extension installed/updated:', details.reason)

  // Perform initial scan
  await performFullScan()

  // Set up periodic scan alarm
  chrome.alarms.create('periodic-scan', {
    periodInMinutes: 60, // Check every hour
  })

  // Set up cleanup alarm for old alerts
  chrome.alarms.create('cleanup-alerts', {
    periodInMinutes: 60 * 24, // Daily
  })

  // Open welcome page on first install
  if (details.reason === 'install') {
    chrome.tabs.create({
      url: chrome.runtime.getURL('welcome.html')
    })
  }
})

// Handle alarm triggers
chrome.alarms.onAlarm.addListener(async (alarm) => {
  if (alarm.name === 'periodic-scan') {
    const shouldScan = await isAutoScanDue()
    if (shouldScan) {
      console.log('[ExtSentinel] Auto-scan triggered')
      await performFullScan()
    }
  }

  if (alarm.name === 'cleanup-alerts') {
    // Clean alerts older than 30 days
    const alerts = await getAlerts()
    const thirtyDaysAgo = Date.now() - 30 * 24 * 60 * 60 * 1000
    const filtered = alerts.filter(a => a.timestamp > thirtyDaysAgo)
    if (filtered.length !== alerts.length) {
      await chrome.storage.local.set({ extsentinel_alerts: filtered })
    }
  }
})

// Listen for messages from popup/content scripts
chrome.runtime.onMessage.addListener((request, _sender, sendResponse) => {
  handleMessage(request).then(sendResponse).catch(err => {
    console.error('[ExtSentinel] Message handler error:', err)
    sendResponse({ error: err.message })
  })
  return true // Keep channel open for async
})

// eslint-disable-next-line @typescript-eslint/no-explicit-any
async function handleMessage(request: Record<string, any>) {
  switch (request.type) {
    case 'SCAN_ALL':
      return await performFullScan()

    case 'GET_SCAN_RESULT':
      return await chrome.storage.local.get('extsentinel_last_scan').then(r => r.extsentinel_last_scan)

    case 'GET_ALERTS':
      return await getAlerts()

    case 'CLEAR_ALERTS':
      await chrome.storage.local.remove('extsentinel_alerts')
      return { success: true }

    case 'TOGGLE_EXTENSION':
      await chrome.management.setEnabled(request.extensionId, request.enabled)
      return { success: true }

    case 'UNINSTALL_EXTENSION':
      await chrome.management.uninstall(request.extensionId, { showConfirmDialog: true })
      return { success: true }

    case 'GET_SETTINGS':
      return await getSettings()

    case 'SAVE_SETTINGS':
      await chrome.storage.local.set({ extsentinel_settings: request.settings })
      // Re-schedule alarms if interval changed
      chrome.alarms.create('periodic-scan', {
        periodInMinutes: request.settings.autoScanInterval * 60,
      })
      return { success: true }

    case 'GET_EXTENSION_DETAILS':
      const exts = await chrome.management.getAll()
      return exts.find(e => e.id === request.extensionId)

    case 'DOM_ALERT':
      // Handle DOM integrity alerts from content script
      await handleDOMAlert(request.data)
      return { success: true }

    default:
      return { error: 'Unknown message type' }
  }
}

/**
 * Perform a full scan of all installed extensions
 */
async function performFullScan(): Promise<ScanResult> {
  console.log('[ExtSentinel] Starting full extension scan...')

  const extensions = await chrome.management.getAll()
  const results: ExtensionRisk[] = []
  const alerts: SecurityAlert[] = []

  // Exclude ourselves from scanning
  const ourId = chrome.runtime.id
  const extensionsToScan = extensions.filter(e => e.id !== ourId)

  for (const ext of extensionsToScan) {
    try {
      const analysis = await analyzeExtension(ext)
      results.push(analysis)

      // Generate alerts for critical/high risk
      if (analysis.riskLevel === 'critical' || analysis.riskLevel === 'high') {
        alerts.push({
          id: `scan-${Date.now()}-${ext.id}`,
          timestamp: Date.now(),
          severity: analysis.riskLevel,
          title: `${analysis.riskLevel === 'critical' ? 'CRITICAL' : 'HIGH'}: ${ext.name}`,
          message: `Risk score: ${analysis.riskScore}/100 - ${analysis.findings.length} security findings detected`,
          extensionName: ext.name,
          techniqueId: analysis.findings[0]?.techniqueId,
        })
      }
    } catch (err) {
      console.error(`[ExtSentinel] Error analyzing ${ext.name}:`, err)
    }
  }

  const summary = generateScanSummary(results)

  const scanResult: ScanResult = {
    timestamp: Date.now(),
    totalExtensions: extensionsToScan.length,
    extensionsScanned: results.length,
    criticalCount: summary.criticalCount,
    highCount: summary.highCount,
    mediumCount: summary.mediumCount,
    lowCount: summary.lowCount,
    safeCount: summary.safeCount,
    extensions: results,
    alerts,
  }

  // Save results
  await saveScanResult(scanResult)

  // Show notification if critical findings
  if (summary.criticalCount > 0) {
    await showNotification(
      'ExtSentinel: Critical Security Alert',
      `Found ${summary.criticalCount} extension(s) with CRITICAL risk level. Open ExtSentinel to review.`
    )
  }

  // Store alerts
  for (const alert of alerts) {
    await addAlert({
      severity: alert.severity,
      title: alert.title,
      message: alert.message,
      extensionName: alert.extensionName,
      techniqueId: alert.techniqueId,
    })
  }

  console.log(`[ExtSentinel] Scan complete: ${results.length} extensions analyzed`)
  return scanResult
}

/**
 * Handle DOM integrity alerts from content scripts
 */
async function handleDOMAlert(data: {
  type: string
  url: string
  description: string
  severity: string
}) {
  const settings = await getSettings()
  if (!settings.domProtectionEnabled) return

  await addAlert({
    severity: data.severity,
    title: `DOM Alert: ${data.type}`,
    message: `${data.description} on ${data.url}`,
    techniqueId: data.type === 'form_tampering'
      ? 'BET.TA0006.001'
      : data.type === 'overlay_injection'
        ? 'BET.TA0002.001'
        : 'BET.TA0005.002',
  })

  if (settings.showNotifications) {
    await showNotification(
      'ExtSentinel: Page Security Alert',
      data.description
    )
  }
}

/**
 * Show browser notification
 */
async function showNotification(title: string, message: string) {
  try {
    await chrome.notifications.create({
      type: 'basic',
      iconUrl: chrome.runtime.getURL('icons/shield48.png'),
      title,
      message,
      priority: 2,
    })
  } catch (err) {
    console.error('[ExtSentinel] Notification error:', err)
  }
}

// Listen for extension installation events
chrome.management.onInstalled.addListener(async (ext) => {
  const settings = await getSettings()
  if (!settings.scanOnInstall) return

  // Quick scan of the newly installed extension
  try {
    const analysis = await analyzeExtension(ext)

    if (analysis.riskLevel === 'critical' || analysis.riskLevel === 'high') {
      await showNotification(
        'ExtSentinel: High-Risk Extension Installed',
        `"${ext.name}" has been flagged with ${analysis.riskLevel} risk level. Review immediately.`
      )

      await addAlert({
        severity: analysis.riskLevel,
        title: `New Extension Alert: ${ext.name}`,
        message: `Risk score: ${analysis.riskScore}/100. ${analysis.findings.length} security concerns detected.`,
        extensionName: ext.name,
      })
    }
  } catch (err) {
    console.error('[ExtSentinel] New extension scan error:', err)
  }
})

// Monitor for enabled/disabled changes
chrome.management.onEnabled.addListener(async (ext) => {
  const settings = await getSettings()
  if (settings.blockHighRiskExtensions) {
    const analysis = await analyzeExtension(ext)
    if (analysis.riskLevel === 'critical') {
      await chrome.management.setEnabled(ext.id, false)
      await showNotification(
        'ExtSentinel: Blocked High-Risk Extension',
        `"${ext.name}" was automatically disabled due to critical risk level.`
      )
    }
  }
})

console.log('[ExtSentinel] Background service worker initialized')
