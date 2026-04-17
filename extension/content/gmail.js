/**
 * Gmail Content Script
 * Monitors Gmail for email opens and triggers analysis
 */

(function() {
  'use strict';
  
  let currentEmailId = null;
  let analysisInProgress = false;
  let debounceTimer = null;
  
  /**
   * Initialize Gmail monitoring
   */
  function init() {
    console.log('PhishGuard AI: Gmail content script loaded');
    
    // Set up mutation observer
    observeEmailOpens();
    
    // Listen for analysis results
    chrome.runtime.onMessage.addListener((message, sender, sendResponse) => {
      if (message.type === 'ANALYSIS_RESULT') {
        handleAnalysisResult(message.result, message.cached);
      }
    });
  }
  
  /**
   * Observe DOM for email open events
   */
  function observeEmailOpens() {
    const observer = new MutationObserver((mutations) => {
      // Debounce to avoid duplicate triggers
      clearTimeout(debounceTimer);
      debounceTimer = setTimeout(() => {
        checkForNewEmail();
      }, 500);
    });
    
    // Observe the main email container
    const targetNode = document.body;
    
    observer.observe(targetNode, {
      childList: true,
      subtree: true
    });
    
    // Also check immediately
    setTimeout(checkForNewEmail, 1000);
  }
  
  /**
   * Check if a new email is open
   */
  function checkForNewEmail() {
    // Look for email message container
    const emailElement = document.querySelector('div[data-message-id]');
    
    if (!emailElement) {
      return;
    }
    
    const emailId = emailElement.getAttribute('data-message-id');
    
    // Check if this is a new email
    if (emailId && emailId !== currentEmailId && !analysisInProgress) {
      currentEmailId = emailId;
      analyzeCurrentEmail();
    }
  }
  
  /**
   * Analyze the currently open email
   */
  async function analyzeCurrentEmail() {
    if (analysisInProgress) {
      return;
    }
    
    analysisInProgress = true;
    
    // Clean up previous UI
    UIInjector.cleanup();
    Highlighter.removeHighlights();
    URLInterceptor.cleanup();
    
    // Show loading state
    UIInjector.showLoadingBadge();
    
    // Parse email
    const emailData = EmailParser.parseGmail();
    
    if (!emailData) {
      console.error('Failed to parse email');
      analysisInProgress = false;
      return;
    }
    
    // Send to background for analysis
    try {
      const response = await chrome.runtime.sendMessage({
        type: 'ANALYZE_EMAIL',
        payload: emailData
      });
      
      if (response && response.result) {
        handleAnalysisResult(response.result, response.cached);
      }
    } catch (error) {
      console.error('Analysis request failed:', error);
      analysisInProgress = false;
    }
  }
  
  /**
   * Handle analysis result from background
   */
  function handleAnalysisResult(result, cached) {
    console.log('Analysis result:', result, 'Cached:', cached);
    
    // Inject verdict badge
    UIInjector.injectBadge(result.verdict, result.final_score, result.confidence);
    
    // Inject explainability card
    UIInjector.injectCard(result);
    
    // Highlight suspicious phrases
    if (result.highlighted_phrases && result.highlighted_phrases.length > 0) {
      Highlighter.highlightPhrases(result.highlighted_phrases);
    }
    
    // Label URLs
    if (result.url_verdicts && result.url_verdicts.length > 0) {
      URLInterceptor.labelUrls(result.url_verdicts);
    }
    
    analysisInProgress = false;
  }
  
  // Initialize when DOM is ready
  if (document.readyState === 'loading') {
    document.addEventListener('DOMContentLoaded', init);
  } else {
    init();
  }
})();
