// Ward Content Script
// Extracts visible page content and sends it for analysis

console.log('[Ward] Content script loaded and running');

// Extract all visible hyperlinks with their associated text and context
function extractVisibleLinks() {
  const links = [];
  const anchors = document.querySelectorAll('a[href], button[onclick]');

  anchors.forEach(element => {
    // Check if element is visible
    const style = window.getComputedStyle(element);
    if (style.display === 'none' || style.visibility === 'hidden' || style.opacity === '0') {
      return;
    }

    const rect = element.getBoundingClientRect();
    const windowHeight = window.innerHeight || document.documentElement.clientHeight;
    const windowWidth = window.innerWidth || document.documentElement.clientWidth;

    // Only include visible elements
    if (rect.bottom < -windowHeight ||
        rect.top > windowHeight * 2 ||
        rect.right < 0 ||
        rect.left > windowWidth ||
        rect.width === 0 ||
        rect.height === 0) {
      return;
    }

    let href = element.href || '';
    const linkText = element.textContent.trim();
    const ariaLabel = element.getAttribute('aria-label') || '';
    const title = element.getAttribute('title') || '';

    // Skip empty links or javascript: links
    if (!href && !element.onclick) {
      return;
    }
    if (href && (href.startsWith('javascript:') || href === '#')) {
      return;
    }

    // Build context information
    const context = {
      text: linkText,
      url: href,
      ariaLabel: ariaLabel,
      title: title,
      isButton: element.tagName.toLowerCase() === 'button' || element.classList.contains('btn') || element.classList.contains('button')
    };

    links.push(context);
  });

  return links;
}

// Extract all visible text content from the page
function extractVisibleContent() {
  const walker = document.createTreeWalker(
    document.body,
    NodeFilter.SHOW_TEXT,
    {
      acceptNode: function(node) {
        const parent = node.parentElement;
        if (!parent) return NodeFilter.FILTER_REJECT;

        // Skip Ward extension's own banner
        if (parent.id === 'ward-warning-banner' || parent.closest('#ward-warning-banner')) {
          return NodeFilter.FILTER_REJECT;
        }

        // Skip scripts, styles, etc.
        const tagName = parent.tagName.toLowerCase();
        if (['script', 'style', 'noscript', 'iframe'].includes(tagName)) {
          return NodeFilter.FILTER_REJECT;
        }

        // Skip if text is empty or just whitespace
        if (!node.textContent.trim()) {
          return NodeFilter.FILTER_REJECT;
        }

        // Check if element is actually visible
        const style = window.getComputedStyle(parent);
        if (style.display === 'none' || style.visibility === 'hidden' || style.opacity === '0') {
          return NodeFilter.FILTER_REJECT;
        }

        // Check if element is in the current viewport or very close to it
        const rect = parent.getBoundingClientRect();
        const windowHeight = window.innerHeight || document.documentElement.clientHeight;
        const windowWidth = window.innerWidth || document.documentElement.clientWidth;

        // Only include elements that are in viewport or just outside it (within 1 viewport height/width)
        // This catches sidebar content but excludes far-off scrolled content
        if (rect.bottom < -windowHeight ||
            rect.top > windowHeight * 2 ||
            rect.right < 0 ||
            rect.left > windowWidth) {
          return NodeFilter.FILTER_REJECT;
        }

        // Skip if element has zero size
        if (rect.width === 0 || rect.height === 0) {
          return NodeFilter.FILTER_REJECT;
        }

        return NodeFilter.FILTER_ACCEPT;
      }
    }
  );

  const textContent = [];
  let node;
  while (node = walker.nextNode()) {
    textContent.push(node.textContent.trim());
  }

  // Join all text with spaces and clean up
  let fullText = textContent.join(' ');
  fullText = fullText.replace(/\s+/g, ' ').trim();

  // Extract content from iframes (for email clients)
  const iframes = document.querySelectorAll('iframe');
  for (const iframe of iframes) {
    try {
      const iframeDoc = iframe.contentDocument || iframe.contentWindow?.document;
      if (iframeDoc && iframeDoc.body) {
        const iframeText = iframeDoc.body.innerText || iframeDoc.body.textContent || '';
        if (iframeText.trim()) {
          fullText += '\n\nIFRAME CONTENT:\n' + iframeText.trim();
          console.log('[Ward Content] Extracted iframe content, length:', iframeText.length);
        }
      }
    } catch (e) {
      // Cross-origin iframe, skip
    }
  }

  return fullText;
}

// Show threat notification banner
function showThreatNotification() {
  // Get the latest analysis result from the response
  // This will be called with the analysis result passed from analyzePage
}

// Show warning banner if malicious content detected
function showWarningBanner(analysisResult) {
  // Check if banner already exists
  if (document.getElementById('ward-warning-banner')) {
    return;
  }

  // Use the judge's detailed reasoning (judgment field) from Stage 2
  const fullJudgment = analysisResult.judgment || analysisResult.analysis || 'Suspicious content detected.';

  // Parse the structured judgment response
  // Expected format:
  // Line 1: THREAT
  // Line 2: Summary sentence
  // Lines 3+: Bullet points with *
  // Last line: Final recommendation (always use ONLY the last line)

  const lines = fullJudgment.split('\n').filter(line => line.trim());
  let summary = 'Suspicious content detected.';
  let details = '';
  let recommendation = '';

  // If judgment contains "SAFE" anywhere, remove the summary body and just show generic threat message
  const containsSafe = fullJudgment.toUpperCase().includes('SAFE');

  // Parse the judgment structure
  if (lines.length > 1 && !containsSafe) {
    // Skip "THREAT" line if present, get summary from line 2
    const startIndex = lines[0].toUpperCase().includes('THREAT') ? 1 : 0;

    // First non-THREAT line is the summary
    if (lines[startIndex]) {
      summary = lines[startIndex].trim();
    }

    // The last line is ALWAYS the recommendation to show in the banner
    if (lines.length > 0) {
      recommendation = lines[lines.length - 1].trim();
    }

    // Collect bullet points (lines starting with * but not the last line)
    const bulletPoints = [];
    for (let i = startIndex + 1; i < lines.length - 1; i++) {
      const line = lines[i].trim();
      if (line.startsWith('*') && !line.startsWith('**')) {
        bulletPoints.push(line.substring(1).trim());
      }
    }

    // Format bullet points as HTML
    if (bulletPoints.length > 0) {
      details = bulletPoints.map(point => `<div style="margin-bottom: 6px;">• ${point}</div>`).join('');
    }
  }

  // Format bold text in summary and recommendation
  summary = summary.replace(/\*\*([^*]+)\*\*/g, '<strong>$1</strong>');
  recommendation = recommendation.trim().replace(/\*\*([^*]+)\*\*/g, '<strong>$1</strong>');

  const banner = document.createElement('div');
  banner.id = 'ward-warning-banner';
  banner.innerHTML = `
    <div style="
      position: fixed;
      top: 0;
      left: 0;
      right: 0;
      background: #E03C31;
      color: white;
      padding: 16px 20px;
      font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif;
      font-size: 14px;
      box-shadow: 0 4px 6px rgba(0, 0, 0, 0.1);
      z-index: 2147483647;
      animation: slideDown 0.3s ease-out;
      max-height: 400px;
      overflow-y: auto;
    ">
      <div style="display: flex; align-items: center; gap: 16px; max-width: 1200px; margin: 0 auto; padding: 0 20px;">
        <div style="position: relative; width: 32px; height: 32px; flex-shrink: 0;">
          <img src="${chrome.runtime.getURL('icons/ward-shield.png')}" width="32" height="32" alt="Ward shield" style="display: block;">
          <div style="position: absolute; bottom: -6px; right: -6px; background: white; border-radius: 50%; width: 24px; height: 24px; display: flex; align-items: center; justify-content: center; border: 2px solid #E03C31;">
            <span style="color: #DC2626; font-size: 16px; font-weight: bold; line-height: 1;">!</span>
          </div>
        </div>
        <div style="text-align: center; flex: 1;">
          <div style="font-weight: 600; margin-bottom: 4px; font-size: 15px;">
            ${recommendation}
          </div>
          <div style="font-size: 13px; opacity: 0.95; display: flex; align-items: center; justify-content: center; gap: 6px;">
            <span>Open the Ward extension</span>
            <div style="position: relative; width: 20px; height: 20px; flex-shrink: 0;">
              <img src="${chrome.runtime.getURL('icons/ward-shield.png')}" width="20" height="20" alt="Ward shield" style="display: block;">
              <div style="position: absolute; bottom: -3px; right: -3px; background: white; border-radius: 50%; width: 12px; height: 12px; display: flex; align-items: center; justify-content: center; border: 1px solid #E03C31;">
                <span style="color: #DC2626; font-size: 8px; font-weight: bold; line-height: 1;">!</span>
              </div>
            </div>
            <span>in your toolbar</span>
          </div>
        </div>
        <button id="ward-close-banner" style="
          background: rgba(255, 255, 255, 0.2);
          border: none;
          color: white;
          padding: 6px 12px;
          border-radius: 6px;
          cursor: pointer;
          font-size: 12px;
          font-weight: 500;
          transition: background 0.2s;
          flex-shrink: 0;
          margin-left: auto;
        " onmouseover="this.style.background='rgba(255,255,255,0.3)'"
           onmouseout="this.style.background='rgba(255,255,255,0.2)'">
          Dismiss
        </button>
      </div>
    </div>
    <style>
      @keyframes slideDown {
        from {
          transform: translateY(-100%);
          opacity: 0;
        }
        to {
          transform: translateY(0);
          opacity: 1;
        }
      }
      @keyframes bounce {
        0%, 100% {
          transform: translateY(0);
        }
        50% {
          transform: translateY(-8px);
        }
      }
      #ward-warning-banner::-webkit-scrollbar {
        width: 8px;
      }
      #ward-warning-banner::-webkit-scrollbar-track {
        background: rgba(0,0,0,0.1);
        border-radius: 4px;
      }
      #ward-warning-banner::-webkit-scrollbar-thumb {
        background: rgba(255,255,255,0.3);
        border-radius: 4px;
      }
      #ward-warning-banner::-webkit-scrollbar-thumb:hover {
        background: rgba(255,255,255,0.4);
      }
    </style>
  `;

  document.body.appendChild(banner);

  // Add close button handler
  document.getElementById('ward-close-banner').addEventListener('click', () => {
    banner.remove();
  });
}

// Show quota exceeded banner
function showQuotaExceededBanner(analysisResult) {
  // Don't show if user already dismissed it
  if (quotaBannerDismissed) {
    return;
  }

  // Check if banner already exists
  if (document.getElementById('ward-quota-banner')) {
    return;
  }

  const quota = analysisResult.quota || { current: '?', limit: '?', tier: 'unknown' };
  const tierName = quota.tier === 'pro' ? 'Pro' : 'Free';

  const banner = document.createElement('div');
  banner.id = 'ward-quota-banner';
  banner.innerHTML = `
    <div style="
      position: fixed;
      top: 0;
      left: 0;
      right: 0;
      background: linear-gradient(135deg, #F59E0B 0%, #D97706 100%);
      color: white;
      padding: 16px 20px;
      font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif;
      font-size: 14px;
      box-shadow: 0 4px 12px rgba(0, 0, 0, 0.15);
      z-index: 2147483647;
      animation: slideDown 0.3s ease-out;
    ">
      <div style="display: flex; align-items: center; gap: 16px; max-width: 1200px; margin: 0 auto; padding: 0 20px;">
        <svg width="28" height="28" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" style="flex-shrink: 0;">
          <circle cx="12" cy="12" r="10"></circle>
          <line x1="12" y1="8" x2="12" y2="12"></line>
          <line x1="12" y1="16" x2="12.01" y2="16"></line>
        </svg>
        <div style="flex: 1;">
          <div style="font-weight: 600; margin-bottom: 4px; font-size: 15px;">
            Daily Quota Exceeded
          </div>
          <div style="font-size: 13px; opacity: 0.95;">
            You've used ${quota.current} of ${quota.limit} scans today (${tierName} tier). ${quota.tier === 'pro' ? 'Your quota resets tomorrow.' : 'Upgrade to Pro for unlimited scans or try again tomorrow.'}
          </div>
        </div>
        <button id="ward-close-quota-banner" style="
          background: transparent;
          border: none;
          color: white;
          padding: 8px;
          cursor: pointer;
          font-size: 20px;
          line-height: 1;
          transition: opacity 0.2s;
          flex-shrink: 0;
          opacity: 0.9;
        " onmouseover="this.style.opacity='1'"
           onmouseout="this.style.opacity='0.9'">
          ×
        </button>
      </div>
    </div>
    <style>
      @keyframes slideDown {
        from {
          transform: translateY(-100%);
          opacity: 0;
        }
        to {
          transform: translateY(0);
          opacity: 1;
        }
      }
    </style>
  `;

  document.body.appendChild(banner);

  // Add close button handler
  document.getElementById('ward-close-quota-banner').addEventListener('click', () => {
    quotaBannerDismissed = true; // Remember user dismissed it
    banner.remove();
  });
}

// Track if analysis is in progress to prevent duplicate requests
let analysisInProgress = false;
let lastAnalyzedContent = '';
let quotaBannerDismissed = false; // Track if user dismissed quota banner

// Analyze page content when loaded
async function analyzePage() {
  try {
    // Prevent multiple simultaneous analyses
    if (analysisInProgress) {
      console.log('[Ward] Analysis already in progress, skipping...');
      return;
    }

    // Skip email inbox list views - only analyze individual message views
    const url = window.location.href;

    // Skip Chrome internal pages (chrome://, chrome-extension://, etc.)
    if (url.startsWith('chrome://') || url.startsWith('chrome-extension://') || url.startsWith('about:')) {
      console.log('[Ward] Skipping Chrome internal page:', url);
      await chrome.runtime.sendMessage({
        action: 'analyzeContent',
        content: '',
        skipped: true
      });
      return;
    }

    // Skip internal/private IP addresses
    const hostname = window.location.hostname;
    const isPrivateIP = /^(localhost|127\.|10\.|172\.(1[6-9]|2[0-9]|3[01])\.|192\.168\.|::1|fe80:)/.test(hostname);
    if (isPrivateIP) {
      console.log('[Ward] Skipping private/internal IP address:', hostname);
      await chrome.runtime.sendMessage({
        action: 'analyzeContent',
        content: '',
        skipped: true
      });
      return;
    }

    // Gmail: Skip inbox list, only analyze individual messages
    if (url.includes('mail.google.com')) {
      // Gmail individual message URLs have format: #inbox/messageId or #label/messageId
      // Inbox list views are just: #inbox or #inbox?compose=new
      const hashPart = url.split('#')[1] || '';
      const pathSegments = hashPart.split('/');

      // If no second segment (after inbox/label), it's a list view
      if (pathSegments.length < 2 || !pathSegments[1]) {
        console.log('[Ward] Skipping Gmail inbox list view - only analyzing individual messages');
        await chrome.runtime.sendMessage({
          action: 'analyzeContent',
          content: '',
          skipped: true
        });
        return;
      }
      console.log('[Ward] Gmail individual message detected, proceeding with analysis');
    }

    // Outlook: Skip inbox list views
    if (url.includes('outlook.live.com') || url.includes('outlook.office.com')) {
      // Outlook message view has /mail/id/ in the URL
      // Inbox list is just /mail/inbox or /mail/0/
      if (!url.includes('/mail/id/')) {
        console.log('[Ward] Skipping Outlook inbox list view - only analyzing individual messages');
        await chrome.runtime.sendMessage({
          action: 'analyzeContent',
          content: '',
          skipped: true
        });
        return;
      }
      console.log('[Ward] Outlook individual message detected, proceeding with analysis');
    }

    // Yahoo Mail: Skip inbox list views
    if (url.includes('mail.yahoo.com')) {
      // Yahoo message view has /.m/ in the URL path
      // Inbox list is just /d/folders/1 or similar
      if (!url.includes('/.m/')) {
        console.log('[Ward] Skipping Yahoo Mail inbox list view - only analyzing individual messages');
        await chrome.runtime.sendMessage({
          action: 'analyzeContent',
          content: '',
          skipped: true
        });
        return;
      }
      console.log('[Ward] Yahoo Mail individual message detected, proceeding with analysis');
    }

    const content = extractVisibleContent();
    const links = extractVisibleLinks();

    if (!content || content.length < 50) {
      console.log('[Ward] Not enough content to analyze (< 50 chars)');
      return;
    }

    // Skip if content hasn't changed significantly (less than 5% difference)
    if (lastAnalyzedContent && Math.abs(content.length - lastAnalyzedContent.length) < lastAnalyzedContent.length * 0.05) {
      console.log('[Ward] Content unchanged, skipping re-analysis');
      return;
    }

    analysisInProgress = true;
    lastAnalyzedContent = content;

    // Build enhanced content with links
    let enhancedContent = content;

    if (links.length > 0) {
      enhancedContent += '\n\nLINKS FOUND ON PAGE:\n';
      links.forEach((link) => {
        const linkType = link.isButton ? '[BUTTON]' : '[LINK]';
        enhancedContent += `${linkType} "${link.text}" → ${link.url}\n`;
        if (link.ariaLabel) enhancedContent += `  (aria-label: ${link.ariaLabel})\n`;
        if (link.title) enhancedContent += `  (title: ${link.title})\n`;
      });
    }

    console.log(`[Ward] Starting analysis of ${content.length} characters...`);
    console.log(`[Ward] Found ${links.length} links`);
    console.log(`[Ward] Content preview:`, content.substring(0, 200) + '...');
    console.log(`[Ward] FULL CONTENT FOR DEBUGGING:`, enhancedContent);

    // Send content to background script for analysis
    const response = await chrome.runtime.sendMessage({
      action: 'analyzeContent',
      content: enhancedContent
    });

    console.log('[Ward] Analysis complete:', {
      isMalicious: response.isMalicious,
      method: response.method,
      contentLength: response.contentLength,
      judgment: response.judgment
    });

    // Check for quota exceeded
    if (response.judgment === 'QUOTA_EXCEEDED') {
      console.log('[Ward] QUOTA EXCEEDED:', response.quota);
      showQuotaExceededBanner(response);
    } else if (response.isMalicious) {
      console.log('[Ward] THREAT DETECTED on this page:', {
        analysis: response.analysis,
        judgment: response.judgment
      });

      // Show banner with threat information
      showWarningBanner(response);

    } else {
      console.log('[Ward] Page appears normal.');
    }

  } catch (error) {
    console.error('[Ward] Failed to analyze page:', error);
  } finally {
    // Always reset the flag so future analyses can run
    analysisInProgress = false;
  }
}

// Run analysis when page loads
if (document.readyState === 'loading') {
  document.addEventListener('DOMContentLoaded', analyzePage);
} else {
  // DOM already loaded
  analyzePage();
}

// Re-analyze if significant DOM changes occur (debounced)
let analysisTimeout;
const observer = new MutationObserver(() => {
  clearTimeout(analysisTimeout);
  analysisTimeout = setTimeout(analyzePage, 2000); // Wait 2 seconds after last change
});

// Start observing after initial load
window.addEventListener('load', () => {
  observer.observe(document.body, {
    childList: true,
    subtree: true
  });
});
