/**
 * Highlighter - Shared Module
 * Highlights suspicious phrases in email body
 */

const Highlighter = {
  /**
   * Highlight phrases in email body
   */
  highlightPhrases(phrases) {
    if (!phrases || phrases.length === 0) {
      return;
    }
    
    // Get email body element
    let bodyElement = null;
    
    if (window.location.hostname.includes('mail.google.com')) {
      bodyElement = document.querySelector('.a3s.aiL');
    } else if (window.location.hostname.includes('outlook')) {
      bodyElement = document.querySelector('[aria-label="Message body"]');
    }
    
    if (!bodyElement) {
      console.log('Could not find email body element');
      return;
    }
    
    // Process each phrase
    phrases.forEach(phrase => {
      this.highlightPhrase(bodyElement, phrase);
    });
  },
  
  /**
   * Highlight a single phrase
   */
  highlightPhrase(container, phrase) {
    const text = phrase.text;
    const severity = phrase.severity;
    const reason = phrase.reason;
    
    // Create a TreeWalker to iterate through text nodes
    const walker = document.createTreeWalker(
      container,
      NodeFilter.SHOW_TEXT,
      null,
      false
    );
    
    const textNodes = [];
    let node;
    while (node = walker.nextNode()) {
      textNodes.push(node);
    }
    
    // Search for phrase in text nodes
    textNodes.forEach(textNode => {
      const content = textNode.textContent;
      const lowerContent = content.toLowerCase();
      const lowerPhrase = text.toLowerCase();
      
      const index = lowerContent.indexOf(lowerPhrase);
      
      if (index !== -1) {
        // Found the phrase
        const before = content.substring(0, index);
        const match = content.substring(index, index + text.length);
        const after = content.substring(index + text.length);
        
        // Create highlight element
        const mark = document.createElement('mark');
        mark.className = 'phishguard-highlight';
        mark.setAttribute('data-reason', reason);
        mark.setAttribute('data-severity', severity);
        mark.textContent = match;
        
        // Apply severity-specific styling
        if (severity === 'HIGH') {
          mark.style.background = '#ffcccc';
          mark.style.borderBottom = '2px solid #cc0000';
        } else if (severity === 'MEDIUM') {
          mark.style.background = '#fff3cc';
          mark.style.borderBottom = '2px solid #cc8800';
        } else {
          mark.style.background = '#e8f4e8';
          mark.style.borderBottom = '2px solid #228822';
        }
        
        mark.style.padding = '2px 4px';
        mark.style.borderRadius = '3px';
        mark.style.cursor = 'help';
        mark.title = reason;
        
        // Replace text node with highlighted version
        const fragment = document.createDocumentFragment();
        if (before) fragment.appendChild(document.createTextNode(before));
        fragment.appendChild(mark);
        if (after) fragment.appendChild(document.createTextNode(after));
        
        textNode.parentNode.replaceChild(fragment, textNode);
      }
    });
  },
  
  /**
   * Remove all highlights
   */
  removeHighlights() {
    const highlights = document.querySelectorAll('.phishguard-highlight');
    highlights.forEach(mark => {
      const text = mark.textContent;
      mark.parentNode.replaceChild(document.createTextNode(text), mark);
    });
  }
};

// Make available globally
window.Highlighter = Highlighter;
