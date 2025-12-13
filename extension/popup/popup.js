document.addEventListener('DOMContentLoaded', async () => {
    const [tab] = await chrome.tabs.query({ active: true, currentWindow: true });
    
    if (!tab || !tab.url.startsWith('http')) {
        document.getElementById('loading').textContent = "N/A";
        return;
    }

    document.getElementById('current-url').textContent = new URL(tab.url).hostname;

    // Ask background to predict
    chrome.runtime.sendMessage({ action: "checkCurrentTab", url: tab.url }, (response) => {
        document.getElementById('loading').style.display = 'none';
        
        if (!response) {
            document.getElementById('loading').textContent = "Model not ready. Please wait...";
            document.getElementById('loading').style.display = 'block';
            document.getElementById('loading').className = 'unknown';
            return;
        }
        
        if (response.result === 'phishing') {
            document.getElementById('status-danger').style.display = 'block';
            const reasonText = response.reason === 'blacklist' ? 'Found in Blacklist' : `ML Confidence: ${(response.score * 100).toFixed(1)}%`;
            document.getElementById('score-danger').textContent = reasonText;
        } else if (response.result === 'safe') {
            document.getElementById('status-safe').style.display = 'block';
            const reasonText = response.reason === 'whitelist' ? 'In Whitelist' : `ML Score: ${((1 - response.score) * 100).toFixed(1)}% Safe`;
            document.getElementById('score-safe').textContent = reasonText;
        } else if (response.result === 'error') {
            document.getElementById('loading').textContent = "Analysis Error. Model may not be loaded.";
            document.getElementById('loading').style.display = 'block';
            document.getElementById('loading').className = 'unknown';
        } else {
            document.getElementById('loading').textContent = "Unknown Status";
            document.getElementById('loading').style.display = 'block';
            document.getElementById('loading').className = 'unknown';
        }
    });

    document.getElementById('btn-whitelist').addEventListener('click', () => {
        chrome.runtime.sendMessage({ action: "addToWhitelist", url: tab.url }, (res) => {
            if (res.success) {
                window.close(); // Close popup on success
                chrome.tabs.reload(tab.id); // Reload tab
            }
        });
    });
});

