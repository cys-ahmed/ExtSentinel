import React, { useState, useEffect } from 'react'
import { Shield, ShieldCheck, Save, RotateCcw, Info } from 'lucide-react'
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from '@/components/ui/card'
import { Button } from '@/components/ui/button'
import { Switch } from '@/components/ui/switch'
import { Label } from '@/components/ui/label'
import { Separator } from '@/components/ui/separator'
import { Select, SelectContent, SelectItem, SelectTrigger, SelectValue } from '@/components/ui/select'
import { Badge } from '@/components/ui/badge'
import type { ExtSentinelSettings } from '@/types'
import { DEFAULT_SETTINGS } from '@/types'

export default function OptionsApp() {
  const [settings, setSettings] = useState<ExtSentinelSettings>(DEFAULT_SETTINGS)
  const [saved, setSaved] = useState(false)
  const [loading, setLoading] = useState(true)

  useEffect(() => {
    loadSettings()
  }, [])

  const loadSettings = async () => {
    try {
      const result = await chrome.runtime.sendMessage({ type: 'GET_SETTINGS' })
      if (result) {
        setSettings({ ...DEFAULT_SETTINGS, ...result })
      }
    } catch (err) {
      console.error('Failed to load settings:', err)
    } finally {
      setLoading(false)
    }
  }

  const saveSettings = async () => {
    try {
      await chrome.runtime.sendMessage({ type: 'SAVE_SETTINGS', settings })
      setSaved(true)
      setTimeout(() => setSaved(false), 2000)
    } catch (err) {
      console.error('Failed to save settings:', err)
    }
  }

  const resetSettings = () => {
    if (confirm('Reset all settings to defaults?')) {
      setSettings(DEFAULT_SETTINGS)
    }
  }

  const updateSetting = <K extends keyof ExtSentinelSettings>(key: K, value: ExtSentinelSettings[K]) => {
    setSettings(prev => ({ ...prev, [key]: value }))
  }

  if (loading) {
    return (
      <div className="min-h-screen bg-gray-50 flex items-center justify-center">
        <div className="text-center">
          <Shield className="w-10 h-10 text-gray-300 mx-auto mb-3 animate-pulse" />
          <p className="text-sm text-gray-500">Loading settings...</p>
        </div>
      </div>
    )
  }

  return (
    <div className="min-h-screen bg-gray-50 py-8 px-4">
      <div className="max-w-2xl mx-auto space-y-6">
        {/* Header */}
        <div className="text-center mb-8">
          <div className="inline-flex items-center justify-center w-14 h-14 rounded-2xl bg-slate-900 mb-4">
            <ShieldCheck className="w-8 h-8 text-emerald-400" />
          </div>
          <h1 className="text-2xl font-bold text-gray-900">ExtSentinel Settings</h1>
          <p className="text-sm text-gray-500 mt-1">Configure your extension security scanner</p>
        </div>

        {/* Scanning Settings */}
        <Card>
          <CardHeader>
            <CardTitle className="text-base flex items-center gap-2">
              <RotateCcw className="w-4 h-4 text-slate-600" />
              Scanning Configuration
            </CardTitle>
            <CardDescription>Control how and when ExtSentinel analyzes your extensions</CardDescription>
          </CardHeader>
          <CardContent className="space-y-6">
            {/* Auto Scan */}
            <div className="flex items-center justify-between">
              <div className="space-y-0.5">
                <Label htmlFor="auto-scan" className="text-sm font-medium">Automatic Scanning</Label>
                <p className="text-xs text-gray-500">Periodically scan all extensions for security issues</p>
              </div>
              <Switch
                id="auto-scan"
                checked={settings.autoScanEnabled}
                onCheckedChange={(v) => updateSetting('autoScanEnabled', v)}
              />
            </div>

            <Separator />

            {/* Scan Interval */}
            <div className="flex items-center justify-between">
              <div className="space-y-0.5">
                <Label className="text-sm font-medium">Scan Interval</Label>
                <p className="text-xs text-gray-500">How often to automatically scan extensions</p>
              </div>
              <Select
                value={String(settings.autoScanInterval)}
                onValueChange={(v) => updateSetting('autoScanInterval', Number(v))}
                disabled={!settings.autoScanEnabled}
              >
                <SelectTrigger className="w-36">
                  <SelectValue />
                </SelectTrigger>
                <SelectContent>
                  <SelectItem value="1">Every hour</SelectItem>
                  <SelectItem value="6">Every 6 hours</SelectItem>
                  <SelectItem value="12">Every 12 hours</SelectItem>
                  <SelectItem value="24">Daily</SelectItem>
                  <SelectItem value="168">Weekly</SelectItem>
                </SelectContent>
              </Select>
            </div>

            <Separator />

            {/* Scan on Install */}
            <div className="flex items-center justify-between">
              <div className="space-y-0.5">
                <Label htmlFor="scan-install" className="text-sm font-medium">Scan on Install</Label>
                <p className="text-xs text-gray-500">Automatically scan new extensions when installed</p>
              </div>
              <Switch
                id="scan-install"
                checked={settings.scanOnInstall}
                onCheckedChange={(v) => updateSetting('scanOnInstall', v)}
              />
            </div>
          </CardContent>
        </Card>

        {/* Protection Settings */}
        <Card>
          <CardHeader>
            <CardTitle className="text-base flex items-center gap-2">
              <Shield className="w-4 h-4 text-slate-600" />
              Real-Time Protection
            </CardTitle>
            <CardDescription>Configure active monitoring and protection features</CardDescription>
          </CardHeader>
          <CardContent className="space-y-6">
            {/* DOM Protection */}
            <div className="flex items-center justify-between">
              <div className="space-y-0.5">
                <Label htmlFor="dom-protection" className="text-sm font-medium">DOM Integrity Monitoring</Label>
                <p className="text-xs text-gray-500">Monitor web pages for suspicious modifications, overlay injections, and form tampering</p>
              </div>
              <Switch
                id="dom-protection"
                checked={settings.domProtectionEnabled}
                onCheckedChange={(v) => updateSetting('domProtectionEnabled', v)}
              />
            </div>

            <Separator />

            {/* Credential Protection */}
            <div className="flex items-center justify-between">
              <div className="space-y-0.5">
                <Label htmlFor="cred-protection" className="text-sm font-medium">Credential Protection</Label>
                <p className="text-xs text-gray-500">Monitor for attempts to intercept passwords and sensitive form data</p>
              </div>
              <Switch
                id="cred-protection"
                checked={settings.credentialProtectionEnabled}
                onCheckedChange={(v) => updateSetting('credentialProtectionEnabled', v)}
              />
            </div>

            <Separator />

            {/* Block High Risk */}
            <div className="flex items-center justify-between">
              <div className="space-y-0.5">
                <div className="flex items-center gap-2">
                  <Label htmlFor="block-risk" className="text-sm font-medium">Auto-Block Critical Extensions</Label>
                  <Badge variant="outline" className="text-[9px] h-4 px-1 bg-amber-50 text-amber-700 border-amber-200">Advanced</Badge>
                </div>
                <p className="text-xs text-gray-500">Automatically disable extensions flagged as critical risk</p>
              </div>
              <Switch
                id="block-risk"
                checked={settings.blockHighRiskExtensions}
                onCheckedChange={(v) => updateSetting('blockHighRiskExtensions', v)}
              />
            </div>
          </CardContent>
        </Card>

        {/* Sensitivity */}
        <Card>
          <CardHeader>
            <CardTitle className="text-base flex items-center gap-2">
              <Info className="w-4 h-4 text-slate-600" />
              Detection Sensitivity
            </CardTitle>
            <CardDescription>Adjust how aggressively ExtSentinel flags potential security issues</CardDescription>
          </CardHeader>
          <CardContent>
            <Select
              value={settings.sensitivityLevel}
              onValueChange={(v) => updateSetting('sensitivityLevel', v as ExtSentinelSettings['sensitivityLevel'])}
            >
              <SelectTrigger className="w-full">
                <SelectValue />
              </SelectTrigger>
              <SelectContent>
                <SelectItem value="strict">
                  <div className="flex flex-col items-start">
                    <span className="font-medium">Strict</span>
                    <span className="text-xs text-gray-500">Flag any suspicious permission or behavior</span>
                  </div>
                </SelectItem>
                <SelectItem value="balanced">
                  <div className="flex flex-col items-start">
                    <span className="font-medium">Balanced</span>
                    <span className="text-xs text-gray-500">Focus on high-risk and known malicious patterns</span>
                  </div>
                </SelectItem>
                <SelectItem value="permissive">
                  <div className="flex flex-col items-start">
                    <span className="font-medium">Permissive</span>
                    <span className="text-xs text-gray-500">Only flag critical and proven threats</span>
                  </div>
                </SelectItem>
              </SelectContent>
            </Select>

            <div className="mt-4 p-3 bg-blue-50 rounded-lg border border-blue-100">
              <div className="flex items-start gap-2">
                <Info className="w-4 h-4 text-blue-600 mt-0.5 flex-shrink-0" />
                <div>
                  <p className="text-xs font-medium text-blue-800 mb-0.5">Detection Coverage</p>
                  <p className="text-[11px] text-blue-700">
                    ExtSentinel monitors for techniques mapped to the Browser Extension Threat (BET) matrix,
                    covering Initial Access, Execution, Persistence, Privilege Escalation, Defense Evasion,
                    Credential Access, Discovery, Collection, Command &amp; Control, Exfiltration, and Impact.
                  </p>
                </div>
              </div>
            </div>
          </CardContent>
        </Card>

        {/* Notifications */}
        <Card>
          <CardHeader>
            <CardTitle className="text-base">Notifications</CardTitle>
            <CardDescription>Control when and how you receive security alerts</CardDescription>
          </CardHeader>
          <CardContent>
            <div className="flex items-center justify-between">
              <div className="space-y-0.5">
                <Label htmlFor="notifications" className="text-sm font-medium">Security Alerts</Label>
                <p className="text-xs text-gray-500">Show browser notifications for critical security findings</p>
              </div>
              <Switch
                id="notifications"
                checked={settings.showNotifications}
                onCheckedChange={(v) => updateSetting('showNotifications', v)}
              />
            </div>
          </CardContent>
        </Card>

        {/* Action Buttons */}
        <div className="flex gap-3 pt-4">
          <Button
            onClick={saveSettings}
            className="flex-1 bg-slate-900 hover:bg-slate-800 h-10"
          >
            <Save className="w-4 h-4 mr-2" />
            {saved ? 'Saved!' : 'Save Settings'}
          </Button>
          <Button
            variant="outline"
            onClick={resetSettings}
            className="h-10"
          >
            <RotateCcw className="w-4 h-4 mr-2" />
            Reset
          </Button>
        </div>

        {/* Footer */}
        <div className="text-center pt-6 pb-8">
          <p className="text-xs text-gray-400">
            ExtSentinel v1.0.0 &middot; Defensive Security Research Tool
          </p>
          <p className="text-[10px] text-gray-300 mt-1">
            Implements detection strategies from the Browser Extension Threat (BET) Matrix
          </p>
        </div>
      </div>
    </div>
  )
}
