/**
 * Email Parser - Shared Module
 * Extracts email fields from Gmail and Outlook Web DOM
 */

const EmailParser = {
  /**
   * Parse email from Gmail DOM
   */
  parseGmail() {
    try {
      // Sender
      const senderElement = document.querySelector('[data-hovercard-id]');
      const senderEmail = senderElement?.getAttribute('data-hovercard-id') || '';
      const senderName = document.querySelector('.gD')?.getAttribute('email') || senderEmail;
      const sender = senderEmail || senderName;
      
      // Subject
      const subject = document.querySelector('h2.hP')?.innerText?.trim() || '';
      
      // Body text
      const bodyElement = document.querySelector('.a3s.aiL');
      const email_text = bodyElement?.innerText || '';
      const email_html = bodyElement?.innerHTML || '';
      
      // URLs
      const urlElements = document.querySelectorAll('.a3s.aiL a[href]');
      const urls = Array.from(urlElements)
        .map(a => a.href)
        .filter(href => href && href.startsWith('http'));
      
      // Recipient name (logged-in user)
      const userElement = document.querySelector('.gb_pb');
      const recipientName = userElement?.innerText?.split(' ')[0] || '';
      
      // Reply-to (from expanded headers if available)
      let reply_to = '';
      const headerElements = document.querySelectorAll('.gE.iv.gt h3');
      for (const header of headerElements) {
        if (header.innerText.toLowerCase().includes('reply-to')) {
          const valueElement = header.nextElementSibling;
          reply_to = valueElement?.innerText || '';
          break;
        }
      }
      
      // Headers (basic)
      const headers = {};
      
      return {
        email_text,
        email_html,
        subject,
        sender,
        reply_to,
        headers,
        urls,
        recipient_name: recipientName
      };
    } catch (error) {
      console.error('Gmail parsing error:', error);
      return null;
    }
  },
  
  /**
   * Parse email from Outlook Web DOM
   */
  parseOutlook() {
    try {
      // Sender
      const senderElement = document.querySelector('[aria-label*="From"]');
      const sender = senderElement?.innerText?.trim() || '';
      
      // Extract email from sender if in format "Name <email>"
      const emailMatch = sender.match(/<(.+?)>/);
      const senderEmail = emailMatch ? emailMatch[1] : sender;
      
      // Subject
      const subjectElement = document.querySelector('[data-testid="subject"]') ||
                            document.querySelector('.allowTextSelection');
      const subject = subjectElement?.innerText?.trim() || '';
      
      // Body
      const bodyElement = document.querySelector('[aria-label="Message body"]');
      const email_text = bodyElement?.innerText || '';
      const email_html = bodyElement?.innerHTML || '';
      
      // URLs
      const urlElements = document.querySelectorAll('[aria-label="Message body"] a[href]');
      const urls = Array.from(urlElements)
        .map(a => a.href)
        .filter(href => href && href.startsWith('http'));
      
      // Recipient name
      const userElement = document.querySelector('[data-testid="persona-name"]');
      const recipientName = userElement?.innerText?.split(' ')[0] || '';
      
      // Reply-to (if different from sender)
      let reply_to = '';
      
      // Headers (basic)
      const headers = {};
      
      return {
        email_text,
        email_html,
        subject,
        sender: senderEmail,
        reply_to,
        headers,
        urls,
        recipient_name: recipientName
      };
    } catch (error) {
      console.error('Outlook parsing error:', error);
      return null;
    }
  },
  
  /**
   * Auto-detect platform and parse
   */
  parse() {
    const hostname = window.location.hostname;
    
    if (hostname.includes('mail.google.com')) {
      return this.parseGmail();
    } else if (hostname.includes('outlook')) {
      return this.parseOutlook();
    }
    
    return null;
  }
};

// Make available globally
window.EmailParser = EmailParser;
