document.addEventListener('DOMContentLoaded', function() {
    const searchInput = document.getElementById('search');
    const passwordList = document.getElementById('passwordList');
    const fillPasswordBtn = document.getElementById('fillPassword');
    const generatePasswordBtn = document.getElementById('generatePassword');

    // Load passwords from storage
    chrome.storage.sync.get(['passwords'], function(result) {
        const passwords = result.passwords || [];
        displayPasswords(passwords);
    });

    // Search functionality
    searchInput.addEventListener('input', function(e) {
        const searchTerm = e.target.value.toLowerCase();
        chrome.storage.sync.get(['passwords'], function(result) {
            const passwords = result.passwords || [];
            const filteredPasswords = passwords.filter(password => 
                password.website.toLowerCase().includes(searchTerm) ||
                password.username.toLowerCase().includes(searchTerm)
            );
            displayPasswords(filteredPasswords);
        });
    });

    // Display passwords in the list
    function displayPasswords(passwords) {
        passwordList.innerHTML = '';
        passwords.forEach(password => {
            const div = document.createElement('div');
            div.className = 'password-item';
            div.textContent = `${password.website} - ${password.username}`;
            div.addEventListener('click', () => selectPassword(password));
            passwordList.appendChild(div);
        });
    }

    // Handle password selection
    function selectPassword(password) {
        chrome.tabs.query({active: true, currentWindow: true}, function(tabs) {
            chrome.tabs.sendMessage(tabs[0].id, {
                action: 'fillPassword',
                password: password
            });
        });
    }

    // Fill password button
    fillPasswordBtn.addEventListener('click', function() {
        chrome.tabs.query({active: true, currentWindow: true}, function(tabs) {
            chrome.tabs.sendMessage(tabs[0].id, {action: 'autoFill'});
        });
    });

    // Generate password button
    generatePasswordBtn.addEventListener('click', function() {
        const password = generateSecurePassword();
        chrome.tabs.query({active: true, currentWindow: true}, function(tabs) {
            chrome.tabs.sendMessage(tabs[0].id, {
                action: 'fillGeneratedPassword',
                password: password
            });
        });
    });

    // Generate a secure password
    function generateSecurePassword() {
        const length = 16;
        const charset = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789!@#$%^&*()_+";
        let password = "";
        for (let i = 0; i < length; i++) {
            const randomIndex = Math.floor(Math.random() * charset.length);
            password += charset[randomIndex];
        }
        return password;
    }
}); 