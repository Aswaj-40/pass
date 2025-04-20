// Listen for messages from the popup
chrome.runtime.onMessage.addListener(function(request, sender, sendResponse) {
    if (request.action === 'fillPassword') {
        fillPasswordFields(request.password);
    } else if (request.action === 'autoFill') {
        autoFillPasswordFields();
    } else if (request.action === 'fillGeneratedPassword') {
        fillGeneratedPassword(request.password);
    }
});

// Fill password fields with selected password
function fillPasswordFields(password) {
    const usernameFields = findUsernameFields();
    const passwordFields = findPasswordFields();

    if (usernameFields.length > 0) {
        usernameFields[0].value = password.username;
        triggerEvent(usernameFields[0], 'input');
        triggerEvent(usernameFields[0], 'change');
    }

    if (passwordFields.length > 0) {
        passwordFields[0].value = password.password;
        triggerEvent(passwordFields[0], 'input');
        triggerEvent(passwordFields[0], 'change');
    }
}

// Automatically fill password fields based on current URL
function autoFillPasswordFields() {
    const currentUrl = window.location.hostname;
    chrome.storage.sync.get(['passwords'], function(result) {
        const passwords = result.passwords || [];
        const matchingPassword = passwords.find(p => 
            currentUrl.includes(p.website.toLowerCase())
        );

        if (matchingPassword) {
            fillPasswordFields(matchingPassword);
        }
    });
}

// Fill generated password
function fillGeneratedPassword(password) {
    const passwordFields = findPasswordFields();
    if (passwordFields.length > 0) {
        passwordFields[0].value = password;
        triggerEvent(passwordFields[0], 'input');
        triggerEvent(passwordFields[0], 'change');
    }
}

// Find username input fields
function findUsernameFields() {
    const selectors = [
        'input[type="text"]',
        'input[type="email"]',
        'input[name*="user"]',
        'input[name*="login"]',
        'input[name*="username"]',
        'input[id*="user"]',
        'input[id*="login"]',
        'input[id*="username"]'
    ];
    return findFields(selectors);
}

// Find password input fields
function findPasswordFields() {
    const selectors = [
        'input[type="password"]',
        'input[name*="pass"]',
        'input[id*="pass"]'
    ];
    return findFields(selectors);
}

// Helper function to find fields using multiple selectors
function findFields(selectors) {
    let fields = [];
    selectors.forEach(selector => {
        const elements = document.querySelectorAll(selector);
        elements.forEach(element => {
            if (isVisible(element)) {
                fields.push(element);
            }
        });
    });
    return fields;
}

// Check if element is visible
function isVisible(element) {
    const style = window.getComputedStyle(element);
    return style.display !== 'none' && 
           style.visibility !== 'hidden' && 
           style.opacity !== '0';
}

// Trigger DOM events
function triggerEvent(element, eventName) {
    const event = new Event(eventName, {
        bubbles: true,
        cancelable: true
    });
    element.dispatchEvent(event);
} 