// Listen for installation
chrome.runtime.onInstalled.addListener(function() {
    // Initialize storage with default values
    chrome.storage.sync.get(['passwords', 'settings'], function(result) {
        if (!result.passwords) {
            chrome.storage.sync.set({passwords: []});
        }
        if (!result.settings) {
            chrome.storage.sync.set({
                settings: {
                    autoFill: true,
                    generateStrongPasswords: true,
                    passwordLength: 16
                }
            });
        }
    });
});

// Listen for messages from content script
chrome.runtime.onMessage.addListener(function(request, sender, sendResponse) {
    if (request.action === 'savePassword') {
        savePassword(request.password);
    } else if (request.action === 'getPasswords') {
        getPasswords(sendResponse);
        return true; // Required for async response
    }
});

// Save new password
function savePassword(password) {
    chrome.storage.sync.get(['passwords'], function(result) {
        const passwords = result.passwords || [];
        passwords.push(password);
        chrome.storage.sync.set({passwords: passwords});
    });
}

// Get all passwords
function getPasswords(callback) {
    chrome.storage.sync.get(['passwords'], function(result) {
        callback(result.passwords || []);
    });
} 