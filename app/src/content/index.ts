/**
 * ExtSentinel Content Script
 * DOM integrity monitoring and phishing protection
 * Runs on all web pages to detect suspicious modifications
 */

import { analyzeDOMMutation } from '@/lib/detectionEngine'

// Only run on HTTP/HTTPS pages
if (window.location.protocol === 'http:' || window.location.protocol === 'https:') {
  initDOMProtection()
}

function initDOMProtection() {
  // Check if protection is enabled
  chrome.storage.local.get('extsentinel_settings').then(result => {
    const settings = (result.extsentinel_settings || {}) as { domProtectionEnabled?: boolean }
    if (settings.domProtectionEnabled !== false) {
      startMonitoring()
    }
  })
}

function startMonitoring() {
  console.log('[ExtSentinel] DOM protection active on', window.location.hostname)

  // Monitor DOM mutations
  const observer = new MutationObserver((mutations) => {
    for (const mutation of mutations) {
      const result = analyzeDOMMutation(mutation, window.location.href)

      if (result.isSuspicious) {
        // Send alert to background script
        chrome.runtime.sendMessage({
          type: 'DOM_ALERT',
          data: {
            type: getAlertType(mutation),
            url: window.location.href,
            description: result.reason || 'Suspicious DOM modification detected',
            severity: result.severity || 'medium',
          },
        }).catch(() => {
          // Extension may not be available
        })

        // Log to console for visibility
        console.warn('[ExtSentinel] DOM Alert:', result.reason)
      }
    }
  })

  // Observe the entire document
  observer.observe(document.documentElement, {
    childList: true,
    subtree: true,
    attributes: true,
    attributeFilter: ['action', 'formaction', 'src', 'href', 'style'],
  })

  // Monitor for form submission interception
  protectForms()

  // Monitor for prototype pollution
  protectPrototypes()

  // Add visual indicator on secure pages
  addSecurityIndicator()
}

/**
 * Determine alert type from mutation
 */
function getAlertType(mutation: MutationRecord): string {
  const addedNodes = Array.from(mutation.addedNodes)

  for (const node of addedNodes) {
    if (node instanceof HTMLElement) {
      if (node.tagName === 'SCRIPT') return 'script_injection'
      if (isInvisibleOverlay(node)) return 'overlay_injection'
      if (node.tagName === 'FORM' || node.querySelector('input[type="password"]')) {
        return 'form_tampering'
      }
    }
  }

  if (mutation.type === 'attributes') {
    if (mutation.attributeName === 'action' || mutation.attributeName === 'formaction') {
      return 'form_tampering'
    }
  }

  return 'dom_mutation'
}

/**
 * Check if element is an invisible overlay
 */
function isInvisibleOverlay(element: HTMLElement): boolean {
  const style = window.getComputedStyle(element)
  const rect = element.getBoundingClientRect()

  const hasOverlayPosition = style.position === 'fixed' || style.position === 'absolute'
  const isNearFullSize = rect.width > window.innerWidth * 0.8 && rect.height > window.innerHeight * 0.5
  const isLowOpacity = parseFloat(style.opacity) < 0.2
  const highZIndex = parseInt(style.zIndex) > 1000 || style.zIndex === '9999'

  return hasOverlayPosition && isNearFullSize && (isLowOpacity || style.backgroundColor === 'transparent') && highZIndex
}

/**
 * Protect form submissions from interception
 */
function protectForms() {
  // Store original submit methods
  const originalSubmit = HTMLFormElement.prototype.submit

  // Monitor for form submit overrides
  Object.defineProperty(HTMLFormElement.prototype, 'submit', {
    get() {
      return originalSubmit
    },
    set(value) {
      // Form submit was overridden - potential credential interception
      console.warn('[ExtSentinel] Form.submit was overridden on', window.location.hostname)

      chrome.runtime.sendMessage({
        type: 'DOM_ALERT',
        data: {
          type: 'form_tampering',
          url: window.location.href,
          description: `Form submission handler was modified on ${window.location.hostname} - potential credential interception attempt`,
          severity: 'high',
        },
      }).catch(() => {})

      // Still allow the override but we've logged it
      Object.defineProperty(HTMLFormElement.prototype, 'submit', {
        value,
        writable: true,
        configurable: true,
      })
    },
    configurable: true,
  })

  // Protect addEventListener for submit events
  const originalAddEventListener = EventTarget.prototype.addEventListener
  EventTarget.prototype.addEventListener = function (
    type: string,
    listener: EventListenerOrEventListenerObject,
    options?: boolean | AddEventListenerOptions
  ) {
    // Log sensitive event listeners
    if (type === 'submit' && this instanceof HTMLFormElement) {
      const action = this.action
      console.log('[ExtSentinel] Submit listener added to form:', action)
    }

    return originalAddEventListener.call(this, type, listener, options)
  }
}

/**
 * Protect critical prototypes from pollution
 */
function protectPrototypes() {
  const criticalMethods = [
    { obj: XMLHttpRequest.prototype, method: 'send' },
    { obj: XMLHttpRequest.prototype, method: 'open' },
  ]

  for (const { obj, method } of criticalMethods) {
    const original = (obj as any)[method]
    Object.defineProperty(obj, method, {
      get() {
        return original
      },
      set(value) {
        console.warn(`[ExtSentinel] ${method} was modified - potential network interception`)
        Object.defineProperty(obj, method, {
          value,
          writable: true,
          configurable: true,
        })
      },
      configurable: true,
    })
  }
}

/**
 * Add a subtle security indicator to the page
 */
function addSecurityIndicator() {
  // Only add on pages with login forms
  const hasLoginForm = document.querySelector('input[type="password"]') !== null
  if (!hasLoginForm) return

  // Create subtle shield indicator near the address bar area
  const indicator = document.createElement('div')
  indicator.id = 'extsentinel-indicator'
  indicator.innerHTML = `
    <div style="
      position: fixed;
      top: 8px;
      right: 8px;
      z-index: 2147483646;
      background: rgba(255, 255, 255, 0.95);
      border: 1px solid #16a34a;
      border-radius: 6px;
      padding: 6px 10px;
      font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif;
      font-size: 12px;
      color: #16a34a;
      box-shadow: 0 2px 8px rgba(0,0,0,0.1);
      display: flex;
      align-items: center;
      gap: 6px;
      cursor: pointer;
      transition: opacity 0.3s;
    " title="ExtSentinel is monitoring this page for security threats">
      <svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.5" stroke-linecap="round" stroke-linejoin="round">
        <path d="M12 22s8-4 8-10V5l-8-3-8 3v7c0 6 8 10 8 10z"/>
      </svg>
      <span style="font-weight: 600;">Protected</span>
    </div>
  `

  // Auto-hide after 5 seconds
  document.body.appendChild(indicator)
  setTimeout(() => {
    const el = document.getElementById('extsentinel-indicator')
    if (el) {
      el.style.opacity = '0'
      setTimeout(() => el.remove(), 300)
    }
  }, 5000)
}
