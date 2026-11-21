import React from 'react'
import { Shield, CheckCircle, Info, ExternalLink, MousePointer2, Layers, AlertCircle, Cpu, Zap, Activity } from 'lucide-react'

export default function WelcomeApp() {
  return (
    <div className="min-h-screen bg-[#0F172A] text-slate-300 font-sans selection:bg-[#00FFA3]/30 selection:text-white">
      <div className="max-w-4xl mx-auto px-6 py-16">
        
        {/* Hero Section */}
        <div className="text-center mb-20 space-y-6">
          <div className="inline-block px-4 py-1 rounded-full border border-[#00FFA3]/30 bg-[#00FFA3]/10 text-[#00FFA3] text-xs font-bold tracking-widest uppercase mb-4">
            Defensive Security Tool
          </div>
          
          <div className="flex justify-center mb-8">
            <div className="w-24 h-24 bg-slate-800/50 rounded-3xl flex items-center justify-center border border-slate-700 shadow-2xl">
              <Shield className="w-12 h-12 text-[#00FFA3]" />
            </div>
          </div>
          
          <h1 className="text-6xl font-extrabold text-white tracking-tight">
            Ext<span className="text-[#00FFA3]">Sentinel</span>
          </h1>
          
          <p className="text-xl text-slate-400 max-w-2xl mx-auto leading-relaxed">
            Browser Extension Security Scanner. Detect malicious extensions, monitor for phishing attempts, and protect your browser from supply chain attacks.
          </p>
        </div>

        {/* Detection Capabilities */}
        <div className="mb-24">
          <div className="space-y-4 mb-10">
            <h2 className="text-3xl font-bold text-white">Detection Capabilities</h2>
            <p className="text-slate-400">
              Implements detection strategies from the Browser Extension Threat (BET) Matrix covering the full MITRE ATT&CK-style kill chain:
            </p>
          </div>

          <div className="grid grid-cols-1 md:grid-cols-2 gap-6">
            <CapabilityCard 
              number="01" 
              title="Permission Analysis" 
              description="Scores 40+ Chrome APIs by risk level. Detects dangerous permission combinations that enable credential theft and session hijacking." 
              icon={Cpu}
            />
            <CapabilityCard 
              number="02" 
              title="Host Access Scanning" 
              description="Identifies extensions with broad host permissions including <all_urls> that enable universal content injection." 
              icon={Layers}
            />
            <CapabilityCard 
              number="03" 
              title="DOM Integrity Monitoring" 
              description="Real-time detection of invisible overlays, form tampering, script injection, and credential harvesting attempts." 
              icon={Activity}
            />
            <CapabilityCard 
              number="04" 
              title="Publisher Verification" 
              description="Flags sideloaded extensions, suspicious naming patterns, external update channels, and missing publisher metadata." 
              icon={CheckCircle}
            />
            <CapabilityCard 
              number="05" 
              title="Supply Chain Detection" 
              description="Monitors for extension updates that escalate permissions, change update URLs, or exhibit trojanization patterns." 
              icon={Zap}
            />
            <CapabilityCard 
              number="06" 
              title="Alert System" 
              description="Real-time notifications for critical findings with technique IDs mapped to the BET matrix for incident response." 
              icon={AlertCircle}
            />
          </div>
        </div>

        {/* Installation */}
        <div className="bg-slate-800/30 border border-slate-700/50 rounded-3xl p-10 mb-20">
          <h2 className="text-3xl font-bold text-white mb-8">Installation</h2>
          <div className="space-y-6">
            <div className="flex gap-4">
              <div className="flex-shrink-0 w-8 h-8 rounded-full bg-slate-700 flex items-center justify-center text-sm font-bold text-slate-300">1</div>
              <p className="text-lg">Download the extension files from this page</p>
            </div>
            
            <div className="flex gap-4 items-start">
              <div className="flex-shrink-0 w-8 h-8 rounded-full bg-slate-700 flex items-center justify-center text-sm font-bold text-slate-300">2</div>
              <div className="space-y-4">
                <p className="text-lg">
                  Open Chrome and navigate to <code className="bg-slate-700 px-2 py-0.5 rounded text-[#00FFA3] font-mono mx-1">chrome://extensions/</code>
                </p>
                <div className="space-y-3">
                  <div className="flex gap-3 items-center text-slate-400">
                    <MousePointer2 className="w-4 h-4 text-[#00FFA3]" />
                    <span>Enable <span className="text-white font-semibold">Developer mode</span> (toggle in top-right corner)</span>
                  </div>
                  <div className="flex gap-3 items-center text-slate-400">
                    <MousePointer2 className="w-4 h-4 text-[#00FFA3]" />
                    <span>Click <span className="text-white font-semibold">Load unpacked</span> and select the extension folder</span>
                  </div>
                  <div className="flex gap-3 items-center text-slate-400">
                    <MousePointer2 className="w-4 h-4 text-[#00FFA3]" />
                    <span>Click the <span className="text-white font-semibold">ExtSentinel icon</span> in your toolbar to run your first scan</span>
                  </div>
                </div>
              </div>
            </div>
          </div>

          <div className="mt-12 p-6 bg-amber-500/10 border border-amber-500/30 rounded-2xl">
            <div className="flex gap-4">
              <Info className="w-6 h-6 text-amber-500 flex-shrink-0 mt-1" />
              <p className="text-sm text-slate-300 leading-relaxed">
                <span className="text-amber-500 font-bold block mb-1 uppercase tracking-wider text-xs">Research Tool Notice</span>
                This is a defensive security research tool designed to help identify potentially malicious browser extensions. It requires the <code className="bg-amber-500/20 px-1.5 py-0.5 rounded text-amber-500 font-mono text-xs">management</code> permission to analyze installed extensions. All analysis is performed locally - no data is sent to external servers.
              </p>
            </div>
          </div>
        </div>

        {/* Footer */}
        <div className="text-center pt-10 border-t border-slate-800 flex flex-col items-center gap-4">
          <div className="flex items-center gap-2 text-slate-500 text-sm">
            <span>ExtSentinel v1.0.0</span>
            <span className="w-1 h-1 rounded-full bg-slate-700"></span>
            <span>Defensive Security Research</span>
            <span className="w-1 h-1 rounded-full bg-slate-700"></span>
            <span>Implements BET Matrix Detection Strategies</span>
          </div>
        </div>

      </div>
    </div>
  )
}

function CapabilityCard({ 
  number, 
  title, 
  description, 
  icon: Icon 
}: { 
  number: string, 
  title: string, 
  description: string,
  icon: any
}) {
  return (
    <div className="group p-8 rounded-3xl bg-slate-800/40 border border-slate-700/50 hover:border-[#00FFA3]/40 transition-all duration-300 hover:shadow-2xl hover:shadow-[#00FFA3]/5">
      <div className="flex justify-between items-start mb-6">
        <div className="text-[#00FFA3] font-mono font-bold text-sm bg-[#00FFA3]/10 px-2 py-0.5 rounded">
          {number}
        </div>
        <Icon className="w-5 h-5 text-slate-500 group-hover:text-[#00FFA3] transition-colors" />
      </div>
      <h3 className="text-xl font-bold text-white mb-3 group-hover:text-[#00FFA3] transition-colors">{title}</h3>
      <p className="text-slate-400 text-sm leading-relaxed">{description}</p>
    </div>
  )
}
