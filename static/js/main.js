// Main JavaScript for Observatory Scanner

document.addEventListener('DOMContentLoaded', function() {
    // Initialize tooltips
    initializeTooltips();
    
    // Setup form validation
    setupFormValidation();
    
    // Setup scan progress tracking
    setupScanProgress();
    
    // Setup auto-refresh for pending scans
    setupAutoRefresh();
    
    // Setup keyboard shortcuts
    setupKeyboardShortcuts();
});

/**
 * Initialize Bootstrap tooltips
 */
function initializeTooltips() {
    const tooltipTriggerList = document.querySelectorAll('[data-bs-toggle="tooltip"]');
    const tooltipList = [...tooltipTriggerList].map(tooltipTriggerEl => 
        new bootstrap.Tooltip(tooltipTriggerEl)
    );
}

/**
 * Setup form validation
 */
function setupFormValidation() {
    const forms = document.querySelectorAll('.needs-validation');
    
    Array.from(forms).forEach(form => {
        form.addEventListener('submit', function(event) {
            if (!form.checkValidity()) {
                event.preventDefault();
                event.stopPropagation();
            }
            
            form.classList.add('was-validated');
        }, false);
    });
    
    // Domain input validation
    const domainInput = document.querySelector('input[name="hostname"]');
    if (domainInput) {
        domainInput.addEventListener('input', function() {
            validateDomainInput(this);
        });
    }
}

/**
 * Validate domain input
 */
function validateDomainInput(input) {
    const value = input.value.trim();
    const domainPattern = /^[a-zA-Z0-9]([a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?(\.[a-zA-Z0-9]([a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?)*$/;
    
    // Remove protocol if present
    const cleanValue = value.replace(/^https?:\/\//, '');
    
    if (cleanValue && !domainPattern.test(cleanValue)) {
        input.setCustomValidity('Please enter a valid domain name');
        input.classList.add('is-invalid');
    } else {
        input.setCustomValidity('');
        input.classList.remove('is-invalid');
        if (cleanValue) {
            input.classList.add('is-valid');
        } else {
            input.classList.remove('is-valid');
        }
    }
}

/**
 * Setup scan progress tracking
 */
function setupScanProgress() {
    const scanButtons = document.querySelectorAll('[href*="scan_domain"], [href*="scan_all"]');
    
    scanButtons.forEach(button => {
        button.addEventListener('click', function(e) {
            if (!confirm('Are you sure you want to start a new scan? This may take a few minutes.')) {
                e.preventDefault();
                return;
            }
            
            showLoadingOverlay('Initiating security scan...');
            
            // Show progress after a short delay
            setTimeout(() => {
                updateLoadingMessage('Analyzing security headers...');
            }, 2000);
            
            setTimeout(() => {
                updateLoadingMessage('Checking content security policies...');
            }, 4000);
            
            setTimeout(() => {
                updateLoadingMessage('Evaluating cookie security...');
            }, 6000);
            
            setTimeout(() => {
                updateLoadingMessage('Finalizing security assessment...');
            }, 8000);
        });
    });
}

/**
 * Show loading overlay
 */
function showLoadingOverlay(message = 'Loading...') {
    const overlay = document.createElement('div');
    overlay.className = 'loading-overlay';
    overlay.id = 'loadingOverlay';
    
    overlay.innerHTML = `
        <div class="text-center text-white">
            <div class="loading-spinner mb-3"></div>
            <h5 id="loadingMessage">${message}</h5>
            <p class="mb-0">Please wait while we analyze the domain security...</p>
        </div>
    `;
    
    document.body.appendChild(overlay);
}

/**
 * Update loading message
 */
function updateLoadingMessage(message) {
    const messageElement = document.getElementById('loadingMessage');
    if (messageElement) {
        messageElement.textContent = message;
    }
}

/**
 * Hide loading overlay
 */
function hideLoadingOverlay() {
    const overlay = document.getElementById('loadingOverlay');
    if (overlay) {
        overlay.remove();
    }
}

/**
 * Setup auto-refresh for pending scans
 */
function setupAutoRefresh() {
    // Check if there are any pending scans by checking badge text content
    const badges = document.querySelectorAll('.badge');
    const pendingScans = Array.from(badges).filter(badge => 
        badge.textContent.includes('Pending') || badge.textContent.includes('Running')
    );
    
    if (pendingScans.length > 0) {
        // Refresh page every 30 seconds
        setTimeout(() => {
            window.location.reload();
        }, 30000);
        
        // Show a notification
        showAutoRefreshNotification();
    }
}

/**
 * Show auto-refresh notification
 */
function showAutoRefreshNotification() {
    const notification = document.createElement('div');
    notification.className = 'alert alert-info alert-dismissible fade show position-fixed';
    notification.style.cssText = 'top: 20px; right: 20px; z-index: 1050; max-width: 300px;';
    
    notification.innerHTML = `
        <i class="fas fa-info-circle me-2"></i>
        <strong>Auto-refresh enabled</strong><br>
        Page will refresh automatically while scans are pending.
        <button type="button" class="btn-close" data-bs-dismiss="alert"></button>
    `;
    
    document.body.appendChild(notification);
    
    // Auto-hide after 5 seconds
    setTimeout(() => {
        notification.remove();
    }, 5000);
}

/**
 * Setup keyboard shortcuts
 */
function setupKeyboardShortcuts() {
    document.addEventListener('keydown', function(e) {
        // Ctrl/Cmd + K: Focus domain input
        if ((e.ctrlKey || e.metaKey) && e.key === 'k') {
            e.preventDefault();
            const domainInput = document.querySelector('input[name="hostname"]');
            if (domainInput) {
                domainInput.focus();
            }
        }
        
        // Ctrl/Cmd + R: Refresh current page (scan all on index)
        if ((e.ctrlKey || e.metaKey) && e.key === 'r' && e.shiftKey) {
            e.preventDefault();
            const scanAllButton = document.querySelector('[href*="scan_all"]');
            if (scanAllButton) {
                scanAllButton.click();
            }
        }
        
        // Escape: Close modals/overlays
        if (e.key === 'Escape') {
            hideLoadingOverlay();
        }
    });
}

/**
 * Format security score with appropriate styling
 */
function formatSecurityScore(score) {
    if (score >= 80) {
        return `<span class="badge bg-success">${score}</span>`;
    } else if (score >= 50) {
        return `<span class="badge bg-warning">${score}</span>`;
    } else {
        return `<span class="badge bg-danger">${score}</span>`;
    }
}

/**
 * Format security grade with appropriate styling
 */
function formatSecurityGrade(grade) {
    const gradeClass = grade.toLowerCase().replace('+', '-plus');
    let badgeClass = 'secondary';
    
    if (['a+', 'a'].includes(grade.toLowerCase())) {
        badgeClass = 'success';
    } else if (['b+', 'b'].includes(grade.toLowerCase())) {
        badgeClass = 'info';
    } else if (['c+', 'c'].includes(grade.toLowerCase())) {
        badgeClass = 'warning';
    } else {
        badgeClass = 'danger';
    }
    
    return `<span class="badge bg-${badgeClass} grade-${gradeClass}">${grade}</span>`;
}

/**
 * Handle CSV export
 */
function exportToCSV() {
    showLoadingOverlay('Generating CSV report...');
    
    // Simulate processing time
    setTimeout(() => {
        window.location.href = '/export_csv';
        hideLoadingOverlay();
    }, 1500);
}

/**
 * Confirm domain removal
 */
function confirmRemoveDomain(domainName) {
    return confirm(`Are you sure you want to remove "${domainName}" from your scan list? This action cannot be undone.`);
}

/**
 * Show success notification
 */
function showSuccessNotification(message) {
    showNotification(message, 'success');
}

/**
 * Show error notification
 */
function showErrorNotification(message) {
    showNotification(message, 'danger');
}

/**
 * Show notification
 */
function showNotification(message, type = 'info') {
    const notification = document.createElement('div');
    notification.className = `alert alert-${type} alert-dismissible fade show position-fixed`;
    notification.style.cssText = 'top: 20px; right: 20px; z-index: 1050; max-width: 400px;';
    
    const icon = type === 'success' ? 'check-circle' : 
                 type === 'danger' ? 'exclamation-triangle' : 
                 'info-circle';
    
    notification.innerHTML = `
        <i class="fas fa-${icon} me-2"></i>
        ${message}
        <button type="button" class="btn-close" data-bs-dismiss="alert"></button>
    `;
    
    document.body.appendChild(notification);
    
    // Auto-hide after 5 seconds
    setTimeout(() => {
        if (notification.parentNode) {
            notification.remove();
        }
    }, 5000);
}

/**
 * Copy text to clipboard
 */
function copyToClipboard(text) {
    navigator.clipboard.writeText(text).then(() => {
        showSuccessNotification('Copied to clipboard!');
    }).catch(() => {
        showErrorNotification('Failed to copy to clipboard');
    });
}

/**
 * Utility function to debounce function calls
 */
function debounce(func, wait) {
    let timeout;
    return function executedFunction(...args) {
        const later = () => {
            clearTimeout(timeout);
            func(...args);
        };
        clearTimeout(timeout);
        timeout = setTimeout(later, wait);
    };
}

// Make functions available globally
window.ObservatoryScanner = {
    formatSecurityScore,
    formatSecurityGrade,
    exportToCSV,
    confirmRemoveDomain,
    showSuccessNotification,
    showErrorNotification,
    copyToClipboard,
    showLoadingOverlay,
    hideLoadingOverlay
};
