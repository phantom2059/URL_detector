// Background Service Worker

importScripts('../lib/onnxruntime-web.min.js');
importScripts('feature_extractor.js');

const MODEL_PATH = '../model/model.onnx';
const BLACKLIST_URL = 'https://raw.githubusercontent.com/JPCERTCC/phishurl-list/main/urls.csv'; // Placeholder, need parsing
// Since JPCERT provides CSV/TXT, we might need a parser or a pre-built JSON.
// For demo, we will use local storage for whitelist and simple caching.

let session = null;
let featureExtractor = new FeatureExtractor();
let whitelist = new Set();
// Blacklist cache (simplified for memory)
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
    const stored = await chrome.storage.local.get(['whitelist', 'blacklist_date']);
    if (stored.whitelist) {
        whitelist = new Set(stored.whitelist);
    }
    
    // TODO: Implement periodic blacklist update from JPCERT
    // For now, empty or mock
}

initModel();
loadLists();

// --- Prediction Logic ---
async function predict(urlStr) {
    if (!session) return null;
    
    // 1. Whitelist Check
    try {
        const urlObj = new URL(urlStr);
        if (whitelist.has(urlObj.hostname)) {
            return { result: 'safe', reason: 'whitelist' };
        }
    } catch (e) { return null; }

    // 2. Blacklist Check
    // if (blacklist.has(urlStr)) return { result: 'phishing', reason: 'blacklist' };

    // 3. ML Check
    try {
        const inputVector = featureExtractor.getVector(urlStr);
        if (!inputVector) return null;

        // Create ONNX tensor
        // CatBoost ONNX usually expects float32 input [1, n_features]
        const tensor = new ort.Tensor('float32', inputVector, [1, inputVector.length]);
        
        const feeds = { 'features': tensor }; 
        // Note: input name 'features' depends on how CatBoost exported it. 
        // Usually it's 'features' or 'float_features'. We might need to check model inputs.
        
        const results = await session.run(feeds);
        
        // Output depends on model. Usually 'probabilities' and 'label'.
        // CatBoost ONNX often outputs 'label' (int64) and 'probabilities' (float32 [1, 2])
        const label = results.label ? results.label.data[0] : 0; // 0 or 1
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
            chrome.notifications.create({
                type: 'basic',
                iconUrl: '../images/icon_danger.png',
                title: 'Phishing Detected!',
                message: `The site ${new URL(tab.url).hostname} appears to be malicious.\nConfidence: ${(prediction.score*100).toFixed(1)}%`,
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

