// Background Service Worker

importScripts('../lib/onnxruntime-web.min.js');
importScripts('feature_extractor.js');

const MODEL_PATH = '../model/model.onnx';
const BLACKLIST_PATH = '../assets/phishurl-list.csv';

let session = null;
let featureExtractor = new FeatureExtractor();
let whitelist = new Set();
let blacklist = new Set(); 

// --- Initialization ---
async function initModel() {
    try {
        console.log("Loading ONNX model...");
        session = await ort.InferenceSession.create(MODEL_PATH);
        console.log("Model loaded successfully.");
    } catch (e) {
        console.error("Failed to load model:", e);
    }
}

async function loadLists() {
    // Load whitelist from storage
    const stored = await chrome.storage.local.get(['whitelist']);
    if (stored.whitelist) {
        whitelist = new Set(stored.whitelist);
    }
    
    // Load blacklist from CSV
    try {
        const response = await fetch(BLACKLIST_PATH);
        const text = await response.text();
        const lines = text.split('\n');
        // Simple CSV parser: assume URL is in 1st or 2nd column depending on format
        // JPCERT format: date,URL,description
        // Header might exist.
        for (let i = 0; i < lines.length; i++) {
            const line = lines[i].trim();
            if (!line) continue;
            // Basic split by comma, ignoring quotes handling for simplicity in this demo
            const parts = line.split(',');
            // Heuristic: check if any part looks like a url
            for (const part of parts) {
                if (part.includes('http') || part.includes('www') || part.includes('.')) {
                    // Strip quotes if present
                    const cleanUrl = part.replace(/^"|"$/g, '');
                    try {
                        const hostname = new URL(cleanUrl).hostname;
                        blacklist.add(cleanUrl); // Add full URL
                        blacklist.add(hostname); // Add hostname too for broader match
                    } catch(e) {
                        blacklist.add(cleanUrl);
                    }
                }
            }
        }
        console.log(`Loaded ${blacklist.size} entries into blacklist.`);
    } catch (e) {
        console.error("Failed to load blacklist:", e);
    }
}

initModel();
loadLists();

// --- Prediction Logic ---
async function predict(urlStr) {
    let urlHostname = "";
    try {
        urlHostname = new URL(urlStr).hostname;
    } catch (e) {
        return null;
    }

    // 1. Whitelist Check
    if (whitelist.has(urlHostname)) {
        return { result: 'safe', reason: 'whitelist' };
    }

    // 2. Blacklist Check
    if (blacklist.has(urlStr) || blacklist.has(urlHostname)) {
        return { result: 'phishing', score: 1.0, reason: 'blacklist' };
    }

    if (!session) return null;

    // 3. ML Check
    try {
        const inputVector = featureExtractor.getVector(urlStr);
        if (!inputVector) return null;

        // Create ONNX tensor
        // CatBoost ONNX usually expects float32 input [1, n_features]
        const tensor = new ort.Tensor('float32', inputVector, [1, inputVector.length]);
        
        const feeds = { 'features': tensor }; 
        
        const results = await session.run(feeds);
        
        // Output depends on model. Usually 'probabilities' and 'label'.
        // CatBoost ONNX often outputs 'label' (int64) and 'probabilities' (float32 [1, 2])
        const label = results.label ? Number(results.label.data[0]) : 0; // 0 or 1
        // Probabilities might be named 'probabilities'
        const probs = results.probabilities ? results.probabilities.data : [0.5, 0.5];
        const phishProb = probs[1];

        if (label === 1 || phishProb > 0.5) {
            return { result: 'phishing', score: phishProb, reason: 'ml' };
        }
        return { result: 'safe', score: phishProb, reason: 'ml' };

    } catch (e) {
        console.error("Prediction error:", e);
        return { result: 'error' };
    }
}

// --- Navigation Listener ---
chrome.tabs.onUpdated.addListener(async (tabId, changeInfo, tab) => {
    if (changeInfo.status === 'complete' && tab.url && tab.url.startsWith('http')) {
        
        // Set icon to loading/neutral first
        chrome.action.setIcon({ path: "../images/icon_neutral.png", tabId: tabId });

        const prediction = await predict(tab.url);
        
        if (prediction && prediction.result === 'phishing') {
            // Alert user!
            chrome.action.setIcon({ path: "../images/icon_danger.png", tabId: tabId });
            chrome.action.setBadgeText({ text: "!", tabId: tabId });
            chrome.action.setBadgeBackgroundColor({ color: "#FF0000", tabId: tabId });
            
            // Show notification
            const reasonText = prediction.reason === 'blacklist' ? "Found in Blacklist" : `ML Confidence: ${(prediction.score*100).toFixed(1)}%`;
            
            chrome.notifications.create({
                type: 'basic',
                iconUrl: '../images/icon_danger.png',
                title: 'Phishing Detected!',
                message: `The site ${new URL(tab.url).hostname} appears to be malicious.\n${reasonText}`,
                priority: 2
            });
            
        } else if (prediction && prediction.result === 'safe') {
            chrome.action.setIcon({ path: "../images/icon_safe.png", tabId: tabId });
            // Remove badge if safe
            chrome.action.setBadgeText({ text: "", tabId: tabId });
        }
    }
});

// --- Message Handler (Popup communication) ---
chrome.runtime.onMessage.addListener((request, sender, sendResponse) => {
    if (request.action === "checkCurrentTab") {
        predict(request.url).then(res => sendResponse(res));
        return true; // async response
    }
    if (request.action === "addToWhitelist") {
        try {
            const hostname = new URL(request.url).hostname;
            whitelist.add(hostname);
            chrome.storage.local.set({ whitelist: Array.from(whitelist) });
            sendResponse({ success: true });
        } catch(e) { sendResponse({ success: false }); }
    }
});
