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
        
        if (response && response.result === 'phishing') {
            document.getElementById('status-danger').style.display = 'block';
            document.getElementById('score-danger').textContent = `Confidence: ${(response.score * 100).toFixed(1)}%`;
        } else if (response && response.result === 'safe') {
            document.getElementById('status-safe').style.display = 'block';
            document.getElementById('score-safe').textContent = `Score: ${(response.score * 100).toFixed(1)}%`;
        } else {
            document.getElementById('loading').textContent = "Error or Unknown";
            document.getElementById('loading').style.display = 'block';
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

