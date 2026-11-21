import React, { useState, useEffect, useCallback } from 'react'
import { Shield, ShieldAlert, ShieldCheck, RefreshCw, Settings, ChevronDown, ChevronUp, AlertTriangle, AlertCircle, Info, X, ExternalLink, Trash2, Power } from 'lucide-react'
import { Card, CardContent, CardHeader, CardTitle } from '@/components/ui/card'
import { Button } from '@/components/ui/button'
import { Badge } from '@/components/ui/badge'
import { Progress } from '@/components/ui/progress'
import { Separator } from '@/components/ui/separator'
import { ScrollArea } from '@/components/ui/scroll-area'
import type { ScanResult, ExtensionRisk, SecurityFinding, RiskLevel } from '@/types'
import { getRiskColor, getRiskBgColor } from '@/lib/detectionEngine'

type Tab = 'overview' | 'extensions' | 'alerts'

export default function PopupApp() {
  const [activeTab, setActiveTab] = useState<Tab>('overview')
  const [scanResult, setScanResult] = useState<ScanResult | null>(null)
  const [isScanning, setIsScanning] = useState(false)
  const [selectedExtension, setSelectedExtension] = useState<ExtensionRisk | null>(null)
  const [alerts, setAlerts] = useState<Array<{ id: string; timestamp: number; severity: string; title: string; message: string }>>([])
  const [lastUpdated, setLastUpdated] = useState<Date | null>(null)

  const loadData = useCallback(async () => {
    try {
      const result = await chrome.runtime.sendMessage({ type: 'GET_SCAN_RESULT' })
      if (result) {
        setScanResult(result)
        setLastUpdated(new Date(result.timestamp))
      }
      const alertData = await chrome.runtime.sendMessage({ type: 'GET_ALERTS' })
      if (alertData) {
        setAlerts(alertData.slice(0, 20))
      }
    } catch (err) {
      console.error('Failed to load data:', err)
    }
  }, [])

  useEffect(() => {
    loadData()
  }, [loadData])

  const runScan = async () => {
    setIsScanning(true)
    try {
      const result = await chrome.runtime.sendMessage({ type: 'SCAN_ALL' })
      if (result) {
        setScanResult(result)
        setLastUpdated(new Date())
        // Reload alerts
        const alertData = await chrome.runtime.sendMessage({ type: 'GET_ALERTS' })
        if (alertData) setAlerts(alertData.slice(0, 20))
      }
    } catch (err) {
      console.error('Scan failed:', err)
    } finally {
      setIsScanning(false)
    }
  }

  const openOptions = () => {
    chrome.runtime.openOptionsPage()
  }

  const dismissAlert = async (alertId: string) => {
    const updated = alerts.filter(a => a.id !== alertId)
    setAlerts(updated)
  }

  const clearAllAlerts = async () => {
    await chrome.runtime.sendMessage({ type: 'CLEAR_ALERTS' })
    setAlerts([])
  }

  const toggleExtension = async (extId: string, enabled: boolean) => {
    await chrome.runtime.sendMessage({ type: 'TOGGLE_EXTENSION', extensionId: extId, enabled })
    // Refresh scan
    await runScan()
  }

  const uninstallExtension = async (extId: string) => {
    await chrome.runtime.sendMessage({ type: 'UNINSTALL_EXTENSION', extensionId: extId })
    // Refresh scan
    await runScan()
  }

  const totalRiskCount = (scanResult?.criticalCount || 0) + (scanResult?.highCount || 0)

  return (
    <div className="w-[420px] min-h-[540px] bg-gray-50 flex flex-col">
      {/* Header */}
      <header className="bg-gradient-to-r from-slate-900 via-slate-800 to-slate-900 text-white px-4 py-3">
        <div className="flex items-center justify-between">
          <div className="flex items-center gap-2.5">
            <div className="relative">
              {totalRiskCount > 0 ? (
                <ShieldAlert className="w-7 h-7 text-red-400" />
              ) : (
                <ShieldCheck className="w-7 h-7 text-emerald-400" />
              )}
              {totalRiskCount > 0 && (
                <span className="absolute -top-1 -right-1 w-4 h-4 bg-red-500 rounded-full text-[10px] flex items-center justify-center font-bold">
                  {totalRiskCount}
                </span>
              )}
            </div>
            <div>
              <h1 className="text-base font-bold leading-tight">ExtSentinel</h1>
              <p className="text-[10px] text-gray-400">Extension Security Scanner</p>
            </div>
          </div>
          <div className="flex items-center gap-1.5">
            <Button
              variant="ghost"
              size="icon"
              className="h-8 w-8 text-gray-400 hover:text-white hover:bg-white/10"
              onClick={runScan}
              disabled={isScanning}
            >
              <RefreshCw className={`w-4 h-4 ${isScanning ? 'animate-spin' : ''}`} />
            </Button>
            <Button
              variant="ghost"
              size="icon"
              className="h-8 w-8 text-gray-400 hover:text-white hover:bg-white/10"
              onClick={openOptions}
            >
              <Settings className="w-4 h-4" />
            </Button>
          </div>
        </div>

        {/* Quick Stats */}
        {scanResult && (
          <div className="flex gap-2 mt-3">
            <StatBadge count={scanResult.criticalCount} label="Critical" color="bg-red-500" />
            <StatBadge count={scanResult.highCount} label="High" color="bg-orange-500" />
            <StatBadge count={scanResult.mediumCount} label="Med" color="bg-yellow-500" />
            <StatBadge count={scanResult.lowCount} label="Low" color="bg-green-500" />
            <div className="flex-1" />
            {lastUpdated && (
              <span className="text-[10px] text-gray-500 self-end">
                {lastUpdated.toLocaleTimeString()}
              </span>
            )}
          </div>
        )}
      </header>

      {/* Tab Navigation */}
      <div className="flex border-b bg-white">
        <TabButton active={activeTab === 'overview'} onClick={() => setActiveTab('overview')}>
          Overview
        </TabButton>
        <TabButton active={activeTab === 'extensions'} onClick={() => setActiveTab('extensions')}>
          Extensions ({scanResult?.extensions.length || 0})
        </TabButton>
        <TabButton active={activeTab === 'alerts'} onClick={() => setActiveTab('alerts')}>
          Alerts {alerts.length > 0 && <span className="ml-1 text-[10px] bg-red-100 text-red-600 px-1.5 py-0.5 rounded-full">{alerts.length}</span>}
        </TabButton>
      </div>

      {/* Content */}
      <ScrollArea className="flex-1">
        <div className="p-3">
          {!scanResult && !isScanning && (
            <EmptyState onScan={runScan} />
          )}

          {isScanning && (
            <ScanningState />
          )}

          {scanResult && activeTab === 'overview' && (
            <OverviewTab
              scanResult={scanResult}
              onViewExtensions={() => setActiveTab('extensions')}
            />
          )}

          {scanResult && activeTab === 'extensions' && !selectedExtension && (
            <ExtensionsTab
              extensions={scanResult.extensions}
              onSelect={setSelectedExtension}
              onToggle={toggleExtension}
              onUninstall={uninstallExtension}
            />
          )}

          {selectedExtension && (
            <ExtensionDetail
              ext={selectedExtension}
              onBack={() => setSelectedExtension(null)}
              onToggle={toggleExtension}
              onUninstall={uninstallExtension}
            />
          )}

          {activeTab === 'alerts' && (
            <AlertsTab
              alerts={alerts}
              onDismiss={dismissAlert}
              onClearAll={clearAllAlerts}
            />
          )}
        </div>
      </ScrollArea>

      {/* Footer */}
      <div className="px-4 py-2 bg-white border-t text-[10px] text-gray-400 text-center">
        Defensive Security Research Tool
      </div>
    </div>
  )
}

// ==================== SUB-COMPONENTS ====================

function StatBadge({ count, label, color }: { count: number; label: string; color: string }) {
  return (
    <div className={`px-2 py-1 rounded-md ${count > 0 ? color : 'bg-gray-200'} ${count > 0 ? 'text-white' : 'text-gray-500'} text-[10px] font-semibold`}>
      {count} {label}
    </div>
  )
}

function TabButton({ active, onClick, children }: { active: boolean; onClick: () => void; children: React.ReactNode }) {
  return (
    <button
      onClick={onClick}
      className={`flex-1 py-2.5 text-xs font-medium transition-colors ${
        active
          ? 'text-slate-900 border-b-2 border-slate-900 bg-slate-50'
          : 'text-gray-500 hover:text-gray-700 hover:bg-gray-50'
      }`}
    >
      {children}
    </button>
  )
}

function EmptyState({ onScan }: { onScan: () => void }) {
  return (
    <div className="text-center py-12">
      <Shield className="w-12 h-12 text-gray-300 mx-auto mb-3" />
      <p className="text-sm text-gray-600 mb-1">No scan data available</p>
      <p className="text-xs text-gray-400 mb-4">Run a scan to analyze your extensions</p>
      <Button onClick={onScan} className="bg-slate-900 hover:bg-slate-800">
        <RefreshCw className="w-4 h-4 mr-2" />
        Run Security Scan
      </Button>
    </div>
  )
}

function ScanningState() {
  return (
    <div className="text-center py-12">
      <RefreshCw className="w-10 h-10 text-slate-600 mx-auto mb-3 animate-spin" />
      <p className="text-sm font-medium text-gray-700 mb-1">Scanning extensions...</p>
      <p className="text-xs text-gray-400">Analyzing permissions, host access, and behavior patterns</p>
    </div>
  )
}

function OverviewTab({ scanResult, onViewExtensions }: { scanResult: ScanResult; onViewExtensions: () => void }) {
  const sorted = [...scanResult.extensions].sort((a, b) => b.riskScore - a.riskScore)
  const topRisks = sorted.slice(0, 5)

  return (
    <div className="space-y-3">
      {/* Risk Summary Card */}
      <Card className="border-0 shadow-sm">
        <CardContent className="pt-4 pb-3 px-4">
          <div className="flex items-center justify-between mb-3">
            <h3 className="text-sm font-semibold text-gray-800">Security Posture</h3>
            <OverallScoreBadge score={calculateOverallScore(scanResult)} />
          </div>
          <div className="space-y-2.5">
            {topRisks.map(ext => (
              <div key={ext.id} className="flex items-center gap-3">
                <div className="w-2 h-2 rounded-full flex-shrink-0" style={{ backgroundColor: getRiskColor(ext.riskLevel) }} />
                <span className="text-xs text-gray-700 flex-1 truncate">{ext.name}</span>
                <div className="flex items-center gap-2">
                  <Progress value={ext.riskScore} className="w-16 h-1.5" />
                  <span className="text-[10px] font-mono w-7 text-right" style={{ color: getRiskColor(ext.riskLevel) }}>
                    {ext.riskScore}
                  </span>
                </div>
              </div>
            ))}
          </div>
          {scanResult.extensions.length > 5 && (
            <Button variant="ghost" size="sm" className="w-full mt-3 text-xs h-8" onClick={onViewExtensions}>
              View all {scanResult.extensions.length} extensions
              <ChevronDown className="w-3 h-3 ml-1" />
            </Button>
          )}
        </CardContent>
      </Card>

      {/* Quick Actions */}
      <Card className="border-0 shadow-sm">
        <CardContent className="py-3 px-4">
          <h3 className="text-sm font-semibold text-gray-800 mb-2">Quick Actions</h3>
          <div className="grid grid-cols-2 gap-2">
            <ActionButton icon={<ExternalLink className="w-3.5 h-3.5" />} label="Extension Store" onClick={() => chrome.tabs.create({ url: 'chrome://extensions/' })} />
            <ActionButton icon={<Settings className="w-3.5 h-3.5" />} label="Settings" onClick={() => chrome.runtime.openOptionsPage()} />
          </div>
        </CardContent>
      </Card>

      {/* Legend */}
      <div className="flex gap-3 px-1 flex-wrap">
        <LegendItem color="#dc2626" label="Critical (80-100)" />
        <LegendItem color="#ea580c" label="High (60-79)" />
        <LegendItem color="#ca8a04" label="Medium (40-59)" />
        <LegendItem color="#16a34a" label="Low/Safe (0-39)" />
      </div>
    </div>
  )
}

function OverallScoreBadge({ score }: { score: number }) {
  let color = 'bg-green-100 text-green-700'
  let text = 'SECURE'
  if (score >= 80) { color = 'bg-red-100 text-red-700'; text = 'CRITICAL' }
  else if (score >= 60) { color = 'bg-orange-100 text-orange-700'; text = 'AT RISK' }
  else if (score >= 40) { color = 'bg-yellow-100 text-yellow-700'; text = 'CAUTION' }

  return (
    <span className={`text-[10px] font-bold px-2 py-0.5 rounded-full ${color}`}>
      {text}
    </span>
  )
}

function calculateOverallScore(result: ScanResult): number {
  if (result.extensions.length === 0) return 0
  const maxScore = Math.max(...result.extensions.map(e => e.riskScore))
  const avgScore = result.extensions.reduce((s, e) => s + e.riskScore, 0) / result.extensions.length
  return Math.round(maxScore * 0.7 + avgScore * 0.3)
}

function ExtensionsTab({
  extensions,
  onSelect,
  onToggle,
  onUninstall,
}: {
  extensions: ExtensionRisk[]
  onSelect: (ext: ExtensionRisk) => void
  onToggle: (id: string, enabled: boolean) => void
  onUninstall: (id: string) => void
}) {
  const [filter, setFilter] = useState<RiskLevel | 'all'>('all')

  const filtered = filter === 'all'
    ? extensions
    : extensions.filter(e => e.riskLevel === filter)

  const sorted = [...filtered].sort((a, b) => b.riskScore - a.riskScore)

  return (
    <div className="space-y-2">
      {/* Filter buttons */}
      <div className="flex gap-1 flex-wrap">
        {(['all', 'critical', 'high', 'medium', 'low', 'safe'] as const).map(level => (
          <button
            key={level}
            onClick={() => setFilter(level)}
            className={`px-2 py-1 rounded text-[10px] font-medium capitalize transition-colors ${
              filter === level
                ? 'bg-slate-900 text-white'
                : 'bg-gray-100 text-gray-600 hover:bg-gray-200'
            }`}
          >
            {level} {level !== 'all' && `(${extensions.filter(e => e.riskLevel === level).length})`}
          </button>
        ))}
      </div>

      {/* Extension list */}
      <div className="space-y-2">
        {sorted.map(ext => (
          <ExtensionCard
            key={ext.id}
            ext={ext}
            onClick={() => onSelect(ext)}
            onToggle={onToggle}
            onUninstall={onUninstall}
          />
        ))}
      </div>
    </div>
  )
}

function ExtensionCard({ ext, onClick, onToggle, onUninstall }: {
  ext: ExtensionRisk
  onClick: () => void
  onToggle: (id: string, enabled: boolean) => void
  onUninstall: (id: string) => void
}) {
  return (
    <Card className="border-0 shadow-sm hover:shadow-md transition-shadow cursor-pointer" onClick={onClick}>
      <CardContent className="p-3">
        <div className="flex items-start gap-3">
          {/* Icon */}
          <div className="w-9 h-9 rounded-lg bg-gray-100 flex items-center justify-center flex-shrink-0 overflow-hidden">
            {ext.iconUrl ? (
              <img src={ext.iconUrl} alt="" className="w-full h-full object-cover" />
            ) : (
              <Shield className="w-5 h-5 text-gray-400" />
            )}
          </div>

          {/* Info */}
          <div className="flex-1 min-w-0">
            <div className="flex items-center gap-2">
              <span className="text-xs font-semibold text-gray-800 truncate">{ext.name}</span>
              <RiskBadge level={ext.riskLevel} />
              {!ext.enabled && (
                <Badge variant="outline" className="text-[9px] h-4 px-1 bg-gray-100">Disabled</Badge>
              )}
            </div>
            <div className="flex items-center gap-2 mt-1">
              <Progress value={ext.riskScore} className="w-20 h-1.5" />
              <span className="text-[10px] font-mono" style={{ color: getRiskColor(ext.riskLevel) }}>
                {ext.riskScore}/100
              </span>
              <span className="text-[10px] text-gray-400">
                {ext.findings.length} finding{ext.findings.length !== 1 ? 's' : ''}
              </span>
            </div>
          </div>

          {/* Actions */}
          <div className="flex items-center gap-1 flex-shrink-0" onClick={e => e.stopPropagation()}>
            <button
              onClick={() => onToggle(ext.id, !ext.enabled)}
              className={`p-1.5 rounded-md transition-colors ${ext.enabled ? 'text-green-600 hover:bg-green-50' : 'text-gray-400 hover:bg-gray-100'}`}
              title={ext.enabled ? 'Disable' : 'Enable'}
            >
              <Power className="w-3.5 h-3.5" />
            </button>
            <button
              onClick={() => onUninstall(ext.id)}
              className="p-1.5 rounded-md text-gray-400 hover:text-red-600 hover:bg-red-50 transition-colors"
              title="Uninstall"
            >
              <Trash2 className="w-3.5 h-3.5" />
            </button>
            <ChevronDown className="w-3.5 h-3.5 text-gray-400" />
          </div>
        </div>
      </CardContent>
    </Card>
  )
}

function ExtensionDetail({ ext, onBack, onToggle, onUninstall }: {
  ext: ExtensionRisk
  onBack: () => void
  onToggle: (id: string, enabled: boolean) => void
  onUninstall: (id: string) => void
}) {
  const [expandedFinding, setExpandedFinding] = useState<string | null>(null)

  return (
    <div className="space-y-3">
      {/* Back button */}
      <Button variant="ghost" size="sm" className="h-8 text-xs" onClick={onBack}>
        <ChevronDown className="w-3.5 h-3.5 mr-1 rotate-90" />
        Back to list
      </Button>

      {/* Extension header */}
      <Card className="border-0 shadow-sm" style={{ backgroundColor: getRiskBgColor(ext.riskLevel) }}>
        <CardContent className="p-4">
          <div className="flex items-center gap-3 mb-3">
            <div className="w-12 h-12 rounded-xl bg-white flex items-center justify-center flex-shrink-0 overflow-hidden shadow-sm">
              {ext.iconUrl ? (
                <img src={ext.iconUrl} alt="" className="w-full h-full object-cover" />
              ) : (
                <Shield className="w-7 h-7 text-gray-400" />
              )}
            </div>
            <div className="flex-1">
              <h2 className="text-sm font-bold text-gray-900">{ext.name}</h2>
              <p className="text-[10px] text-gray-500">v{ext.version} &middot; {ext.installType}</p>
            </div>
            <div className="text-center">
              <div className="text-2xl font-bold" style={{ color: getRiskColor(ext.riskLevel) }}>
                {ext.riskScore}
              </div>
              <div className="text-[9px] text-gray-500">/ 100</div>
            </div>
          </div>

          <div className="flex items-center gap-2 mb-3">
            <RiskBadge level={ext.riskLevel} size="lg" />
            {!ext.enabled && <Badge variant="outline" className="bg-white">Currently Disabled</Badge>}
          </div>

          <p className="text-xs text-gray-600 mb-3">{ext.description}</p>

          {/* Actions */}
          <div className="flex gap-2">
            <Button
              size="sm"
              variant={ext.enabled ? 'outline' : 'default'}
              className={`text-xs h-8 flex-1 ${!ext.enabled ? 'bg-slate-900 hover:bg-slate-800' : ''}`}
              onClick={() => onToggle(ext.id, !ext.enabled)}
            >
              <Power className="w-3.5 h-3.5 mr-1.5" />
              {ext.enabled ? 'Disable Extension' : 'Enable Extension'}
            </Button>
            <Button
              size="sm"
              variant="outline"
              className="text-xs h-8 text-red-600 hover:bg-red-50 hover:text-red-700 border-red-200"
              onClick={() => onUninstall(ext.id)}
            >
              <Trash2 className="w-3.5 h-3.5 mr-1.5" />
              Remove
            </Button>
          </div>
        </CardContent>
      </Card>

      {/* Permissions */}
      <Card className="border-0 shadow-sm">
        <CardHeader className="pb-2 pt-3 px-4">
          <CardTitle className="text-xs font-semibold text-gray-700">Permissions ({ext.permissions.length})</CardTitle>
        </CardHeader>
        <CardContent className="px-4 pb-3">
          <div className="flex flex-wrap gap-1">
            {ext.permissions.map(perm => (
              <Badge key={perm} variant="secondary" className="text-[10px] h-5 px-1.5 font-normal">
                {perm}
              </Badge>
            ))}
            {ext.permissions.length === 0 && (
              <span className="text-[10px] text-gray-400">No permissions declared</span>
            )}
          </div>
        </CardContent>
      </Card>

      {/* Host Permissions */}
      {ext.hostPermissions.length > 0 && (
        <Card className="border-0 shadow-sm">
          <CardHeader className="pb-2 pt-3 px-4">
            <CardTitle className="text-xs font-semibold text-gray-700">Host Access ({ext.hostPermissions.length})</CardTitle>
          </CardHeader>
          <CardContent className="px-4 pb-3">
            <div className="flex flex-wrap gap-1">
              {ext.hostPermissions.map(host => (
                <Badge key={host} variant="outline" className={`text-[10px] h-5 px-1.5 font-normal ${host === '<all_urls>' ? 'border-red-300 text-red-600 bg-red-50' : ''}`}>
                  {host}
                </Badge>
              ))}
            </div>
          </CardContent>
        </Card>
      )}

      {/* Findings */}
      <Card className="border-0 shadow-sm">
        <CardHeader className="pb-2 pt-3 px-4">
          <CardTitle className="text-xs font-semibold text-gray-700">
            Security Findings ({ext.findings.length})
          </CardTitle>
        </CardHeader>
        <CardContent className="px-4 pb-3 space-y-2">
          {ext.findings.map(finding => (
            <div
              key={finding.id}
              className="border rounded-lg overflow-hidden"
              style={{ borderColor: getRiskColor(finding.severity) + '40' }}
            >
              <button
                className="w-full flex items-center gap-2 p-2.5 text-left hover:bg-gray-50 transition-colors"
                onClick={() => setExpandedFinding(expandedFinding === finding.id ? null : finding.id)}
              >
                <SeverityIcon severity={finding.severity} />
                <span className="text-xs font-medium text-gray-800 flex-1">{finding.title}</span>
                {finding.techniqueId && (
                  <Badge variant="outline" className="text-[9px] h-4 px-1 font-mono">
                    {finding.techniqueId}
                  </Badge>
                )}
                {expandedFinding === finding.id ? (
                  <ChevronUp className="w-3 h-3 text-gray-400" />
                ) : (
                  <ChevronDown className="w-3 h-3 text-gray-400" />
                )}
              </button>
              {expandedFinding === finding.id && (
                <div className="px-3 pb-3 pt-1 bg-gray-50 border-t">
                  <p className="text-[11px] text-gray-600 mb-2">{finding.description}</p>
                  {finding.evidence && (
                    <div className="mb-2 p-1.5 bg-gray-100 rounded text-[10px] font-mono text-gray-500 break-all">
                      {finding.evidence}
                    </div>
                  )}
                  <div className="flex items-start gap-1.5">
                    <Info className="w-3 h-3 text-blue-500 mt-0.5 flex-shrink-0" />
                    <p className="text-[10px] text-blue-700">{finding.recommendation}</p>
                  </div>
                </div>
              )}
            </div>
          ))}
        </CardContent>
      </Card>
    </div>
  )
}

function AlertsTab({
  alerts,
  onDismiss,
  onClearAll,
}: {
  alerts: Array<{ id: string; timestamp: number; severity: string; title: string; message: string }>
  onDismiss: (id: string) => void
  onClearAll: () => void
}) {
  if (alerts.length === 0) {
    return (
      <div className="text-center py-12">
        <ShieldCheck className="w-10 h-10 text-green-300 mx-auto mb-2" />
        <p className="text-sm text-gray-500">No alerts</p>
        <p className="text-xs text-gray-400">Security alerts will appear here</p>
      </div>
    )
  }

  return (
    <div className="space-y-2">
      <div className="flex items-center justify-between">
        <span className="text-xs text-gray-500">{alerts.length} alert{alerts.length !== 1 ? 's' : ''}</span>
        <Button variant="ghost" size="sm" className="h-7 text-xs text-gray-500" onClick={onClearAll}>
          Clear all
        </Button>
      </div>

      {alerts.map(alert => (
        <Card key={alert.id} className="border-0 shadow-sm">
          <CardContent className="p-3">
            <div className="flex items-start gap-2.5">
              <SeverityIcon severity={alert.severity as RiskLevel} />
              <div className="flex-1 min-w-0">
                <div className="flex items-center gap-2">
                  <span className="text-xs font-semibold text-gray-800">{alert.title}</span>
                </div>
                <p className="text-[11px] text-gray-600 mt-0.5">{alert.message}</p>
                <span className="text-[9px] text-gray-400 mt-1 block">
                  {new Date(alert.timestamp).toLocaleString()}
                </span>
              </div>
              <button
                onClick={() => onDismiss(alert.id)}
                className="p-1 rounded hover:bg-gray-100 text-gray-400 hover:text-gray-600 transition-colors"
              >
                <X className="w-3 h-3" />
              </button>
            </div>
          </CardContent>
        </Card>
      ))}
    </div>
  )
}

// ==================== UTILITY COMPONENTS ====================

function RiskBadge({ level, size = 'sm' }: { level: RiskLevel; size?: 'sm' | 'lg' }) {
  const labels: Record<RiskLevel, string> = {
    critical: 'CRITICAL',
    high: 'HIGH',
    medium: 'MEDIUM',
    low: 'LOW',
    safe: 'SAFE',
  }

  return (
    <span
      className={`inline-flex items-center font-bold rounded ${
        size === 'lg' ? 'text-[10px] px-2 py-0.5' : 'text-[9px] px-1.5 py-0.5'
      }`}
      style={{
        backgroundColor: getRiskColor(level) + '20',
        color: getRiskColor(level),
      }}
    >
      {labels[level]}
    </span>
  )
}

function SeverityIcon({ severity }: { severity: RiskLevel | string }) {
  const color = getRiskColor(severity as RiskLevel)
  switch (severity) {
    case 'critical':
      return <AlertCircle className="w-4 h-4 flex-shrink-0" style={{ color }} />
    case 'high':
      return <AlertTriangle className="w-4 h-4 flex-shrink-0" style={{ color }} />
    default:
      return <Info className="w-4 h-4 flex-shrink-0" style={{ color: color || '#6b7280' }} />
  }
}

function ActionButton({ icon, label, onClick }: { icon: React.ReactNode; label: string; onClick: () => void }) {
  return (
    <button
      onClick={onClick}
      className="flex items-center justify-center gap-1.5 py-2 px-3 bg-gray-50 hover:bg-gray-100 rounded-lg text-xs text-gray-700 transition-colors"
    >
      {icon}
      {label}
    </button>
  )
}

function LegendItem({ color, label }: { color: string; label: string }) {
  return (
    <div className="flex items-center gap-1">
      <div className="w-2 h-2 rounded-full" style={{ backgroundColor: color }} />
      <span className="text-[9px] text-gray-500">{label}</span>
    </div>
  )
}
