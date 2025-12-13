document.addEventListener('DOMContentLoaded', async () => {
    // UI Elements
    const tabs = document.querySelectorAll('.tab-btn');
    const contents = document.querySelectorAll('.tab-content');
    const themeToggle = document.getElementById('theme-toggle');
    const whitelistList = document.getElementById('whitelist-list');
    const whitelistSearch = document.getElementById('whitelist-search');
    const btnAddWhitelist = document.getElementById('btn-add-whitelist');
    
    // Stats elements
    const statsSitesChecked = document.getElementById('stats-sites-checked');
    const statsPhishingBlocked = document.getElementById('stats-phishing-blocked');
    const statsSafeVisited = document.getElementById('stats-safe-visited');
    
    // State
    let currentTabUrl = "";
    let currentHostname = "";
    let isInWhitelist = false;

    // --- Theme Management ---
    function loadTheme() {
        chrome.storage.local.get(['theme'], (result) => {
            const isDark = result.theme !== 'light';
            document.body.classList.toggle('light-mode', !isDark);
            themeToggle.checked = isDark;
        });
    }

    themeToggle?.addEventListener('change', (e) => {
        const theme = e.target.checked ? 'dark' : 'light';
        document.body.classList.toggle('light-mode', theme === 'light');
        chrome.storage.local.set({ theme });
    });

    loadTheme();

    // --- Tab Management ---
    tabs.forEach(tab => {
        tab.addEventListener('click', () => {
            tabs.forEach(t => t.classList.remove('active'));
            contents.forEach(c => c.classList.remove('active'));
            
            tab.classList.add('active');
            document.getElementById(tab.dataset.tab).classList.add('active');
            
            if (tab.dataset.tab === 'whitelist') {
                renderWhitelist();
            }
            if (tab.dataset.tab === 'settings') {
                loadStats();
            }
        });
    });

    // --- Status Logic ---
    const [tab] = await chrome.tabs.query({ active: true, currentWindow: true });
    
    if (tab && tab.url && tab.url.startsWith('http')) {
        currentTabUrl = tab.url;
        try {
            currentHostname = new URL(tab.url).hostname;
            document.getElementById('current-url').textContent = currentHostname;
        } catch {
            document.getElementById('current-url').textContent = "Invalid URL";
        }

        // Check URL
        chrome.runtime.sendMessage({ action: "checkCurrentTab", url: tab.url }, (response) => {
            document.getElementById('loading').style.display = 'none';
            const resultCard = document.getElementById('result-card');
            const resultIcon = document.getElementById('result-icon');
            const resultTitle = document.getElementById('result-title');
            const resultDesc = document.getElementById('result-desc');

            resultCard.style.display = 'block';

            if (!response) {
                resultIcon.textContent = "⏳";
                resultTitle.textContent = "Loading...";
                resultTitle.className = "status-title warning-text";
                resultDesc.textContent = "Please wait...";
                return;
            }

            if (response.result === 'phishing') {
                resultIcon.textContent = "⚠️";
                resultTitle.textContent = "Phishing Detected";
                resultTitle.className = "status-title danger-text";
                
                const reasonMap = {
                    'blacklist': 'Found in known blacklist',
                    'ml': `ML Confidence: ${(response.score * 100).toFixed(1)}%`
                };
                resultDesc.textContent = reasonMap[response.reason] || "Suspicious activity detected";
                
            } else if (response.result === 'safe') {
                resultIcon.textContent = "✅";
                resultTitle.textContent = "Safe Website";
                resultTitle.className = "status-title safe-text";
                
                const reasonMap = {
                    'whitelist': 'In your whitelist',
                    'global_safe': 'Verified safe domain (Tranco Top 10K)',
                    'ml': `Safety Score: ${((1 - response.score) * 100).toFixed(1)}%`
                };
                resultDesc.textContent = reasonMap[response.reason] || "No threats detected";
                
                if (response.reason === 'whitelist') {
                    isInWhitelist = true;
                    btnAddWhitelist.textContent = "Remove from Whitelist";
                }
            } else {
                resultIcon.textContent = "❓";
                resultTitle.textContent = "Unknown Status";
                resultDesc.textContent = response.error || "Analysis in progress...";
            }
        });
    } else {
        document.getElementById('loading').style.display = 'none';
        document.getElementById('current-url').textContent = "System Page";
        btnAddWhitelist.style.display = 'none';
    }

    // --- Whitelist Management ---
    function renderWhitelist(filter = "") {
        chrome.runtime.sendMessage({ action: "getWhitelist" }, (list) => {
            whitelistList.innerHTML = '';
            
            const filtered = (list || []).filter(domain => domain.includes(filter.toLowerCase()));

            if (filtered.length === 0) {
                whitelistList.innerHTML = '<div style="text-align: center; padding: 20px; opacity: 0.5;">No items found</div>';
                return;
            }

            filtered.forEach(domain => {
                const item = document.createElement('div');
                item.className = 'whitelist-item';
                
                const text = document.createElement('span');
                text.textContent = domain;
                
                const delBtn = document.createElement('button');
                delBtn.className = 'delete-btn';
                delBtn.textContent = '✕';
                delBtn.onclick = () => removeDomain(domain);
                
                item.appendChild(text);
                item.appendChild(delBtn);
                whitelistList.appendChild(item);
            });
        });
    }

    function removeDomain(domain) {
        chrome.runtime.sendMessage({ action: "removeFromWhitelist", hostname: domain }, () => {
            renderWhitelist(whitelistSearch.value);
        });
    }

    btnAddWhitelist?.addEventListener('click', async () => {
        if (!currentHostname) return;
        
        if (isInWhitelist) {
            // Remove from whitelist
            chrome.runtime.sendMessage({ 
                action: "removeFromWhitelist", 
                hostname: currentHostname.replace(/^www\./, '') 
            }, () => {
                chrome.tabs.reload(tab.id);
                window.close();
            });
        } else {
            // Add to whitelist
            chrome.runtime.sendMessage({ 
                action: "addToWhitelist", 
                url: currentTabUrl 
            }, (res) => {
                if (res?.success) {
                    chrome.tabs.reload(tab.id);
                    window.close();
                }
            });
        }
    });

    whitelistSearch?.addEventListener('input', (e) => renderWhitelist(e.target.value));

    // --- Stats ---
    function loadStats() {
        chrome.runtime.sendMessage({ action: "getStats" }, (stats) => {
            if (statsSitesChecked) statsSitesChecked.textContent = stats?.sitesChecked || 0;
            if (statsPhishingBlocked) statsPhishingBlocked.textContent = stats?.phishingBlocked || 0;
            if (statsSafeVisited) statsSafeVisited.textContent = stats?.safeVisited || 0;
        });
    }
});
