// Background Service Worker v1.2

importScripts('../lib/onnxruntime-web.min.js');
importScripts('feature_extractor.js');

// Configure ONNX Runtime
ort.env.wasm.wasmPaths = {
    'ort-wasm.wasm': '../lib/ort-wasm.wasm',
    'ort-wasm-simd.wasm': '../lib/ort-wasm-simd.wasm'
};
ort.env.wasm.numThreads = 1;

const MODEL_PATH = '../model/model.onnx';
const BLACKLIST_PATH = '../assets/phishurl-list.csv';
const SAFELIST_PATH = '../assets/safe-domains.json';

let session = null;
let featureExtractor = new FeatureExtractor();
let whitelist = new Set();
let globalSafeList = new Set();
let blacklist = new Set();

// Stats
let stats = { sitesChecked: 0, phishingBlocked: 0, safeVisited: 0 };

// Stats

// --- Initialization ---
async function initModel() {
    try {
        console.log("Loading ONNX model...");
        session = await ort.InferenceSession.create(MODEL_PATH, { executionProviders: ['wasm'] });
        console.log("Model loaded. Inputs:", session.inputNames, "Outputs:", session.outputNames);
    } catch (e) {
        console.error("Model load failed:", e);
        session = null;
    }
}


async function loadLists() {
    // Load whitelist from storage
    const stored = await chrome.storage.local.get(['whitelist', 'stats']);
    if (stored.whitelist) {
        whitelist = new Set(stored.whitelist);
        console.log(`User whitelist: ${whitelist.size} entries`);
    }
    if (stored.stats) {
        stats = stored.stats;
    }

    // Load Global Safe List (Tranco Top 10K)
    try {
        const url = chrome.runtime.getURL('assets/safe-domains.json');
        const response = await fetch(url);
        if (response.ok) {
            const domains = await response.json();
            domains.forEach(d => globalSafeList.add(d));
            console.log(`Global safe list: ${globalSafeList.size} entries (Tranco Top 10K)`);
        }
    } catch (e) {
        console.error("Safe list load failed:", e);
    }
    
    // Load blacklist (optimized: only store hostnames)
    try {
        const url = chrome.runtime.getURL('assets/phishurl-list.csv');
        const response = await fetch(url);
        const text = await response.text();
        const lines = text.split('\n');
        
        for (const line of lines) {
            const cleanUrl = line.trim().replace(/^"|"$/g, '');
            if (!cleanUrl) continue;
            
            try {
                const urlObj = new URL(cleanUrl.startsWith('http') ? cleanUrl : `https://${cleanUrl}`);
                blacklist.add(urlObj.hostname);
            } catch {
                blacklist.add(cleanUrl);
            }
        }
        console.log(`Blacklist: ${blacklist.size} entries`);
    } catch (e) {
        console.error("Blacklist load failed:", e);
    }
}

// Initialize everything
Promise.all([initModel(), loadLists()]).then(() => {
    console.log("Extension fully initialized!");
});

// --- Fast Domain Check ---
function isInSafeList(hostname) {
    const normalized = hostname.replace(/^www\./, '');
    
    // Direct match
    if (globalSafeList.has(normalized) || globalSafeList.has(hostname)) {
        return true;
    }
    
    // Check parent domains (e.g., mail.google.com -> google.com)
    const parts = normalized.split('.');
    for (let i = 1; i < parts.length - 1; i++) {
        const parent = parts.slice(i).join('.');
        if (globalSafeList.has(parent)) {
            return true;
        }
    }
    
    return false;
}

// --- Prediction Logic ---
async function predict(urlStr) {
    let urlHostname = "";
    try {
        urlHostname = new URL(urlStr).hostname;
    } catch {
        return null;
    }

    const normalized = urlHostname.replace(/^www\./, '');

    // 1. User Whitelist (instant)
    if (whitelist.has(urlHostname) || whitelist.has(normalized)) {
        return { result: 'safe', reason: 'whitelist', score: 0.0 };
    }

    // 2. Global Safe List (fast)
    if (isInSafeList(urlHostname)) {
        return { result: 'safe', reason: 'global_safe', score: 0.0 };
    }

    // 3. Blacklist (fast Set lookup)
    if (blacklist.has(urlHostname) || blacklist.has(normalized)) {
        return { result: 'phishing', score: 1.0, reason: 'blacklist' };
    }

    // 4. ML Check
    if (!session) {
        return { result: 'error', reason: 'model_not_loaded' };
    }

    try {
        const inputVector = featureExtractor.getVector(urlStr);
        if (!inputVector) {
            return { result: 'error', reason: 'feature_extraction_failed' };
        }

        const tensor = new ort.Tensor('float32', new Float32Array(inputVector), [1, inputVector.length]);
        
        let results;
        try {
            results = await session.run({ 'features': tensor });
        } catch {
            results = await session.run({ 'features': tensor }, ['label']);
        }

        const label = results.label ? Number(results.label.data[0]) : 0;
        let phishProb = results.probabilities ? results.probabilities.data[1] || 0 : (label === 1 ? 0.99 : 0.01);

        if (label === 1 || phishProb > 0.5) {
            return { result: 'phishing', score: phishProb, reason: 'ml' };
        }
        return { result: 'safe', score: phishProb, reason: 'ml' };

    } catch (e) {
        console.error("Prediction error:", e);
        return { result: 'error', reason: 'prediction_failed', error: e.message };
    }
}

// --- Icon Update (Pre-rendered icons for instant display) ---
function updateIcon(tabId, status) {
    // Use pre-rendered avatar icons with status dots
    const iconType = status === 'safe' ? 'safe' : 
                    (status === 'phishing' ? 'danger' : 'neutral');
    
    chrome.action.setIcon({
        path: {
            "16": `images/avatar_${iconType}_16.png`,
            "48": `images/avatar_${iconType}_48.png`,
            "128": `images/avatar_${iconType}_128.png`
        },
        tabId: tabId
    });
}

// --- Navigation Listener ---
chrome.tabs.onUpdated.addListener(async (tabId, changeInfo, tab) => {
    if (changeInfo.status === 'loading' && tab.url?.startsWith('http')) {
        await updateIcon(tabId, 'loading');
        return;
    }

    if (changeInfo.status === 'complete' && tab.url?.startsWith('http')) {
        const prediction = await predict(tab.url);
        stats.sitesChecked++;
        
        if (prediction?.result === 'phishing') {
            stats.phishingBlocked++;
            await updateIcon(tabId, 'phishing');
            chrome.action.setBadgeText({ text: "!", tabId });
            chrome.action.setBadgeBackgroundColor({ color: "#FF0000", tabId });
            
            chrome.notifications.create({
                type: 'basic',
                iconUrl: chrome.runtime.getURL('images/icon_danger.png'),
                title: 'Phishing Detected!',
                message: `${new URL(tab.url).hostname} is suspicious!`,
                priority: 2
            });
            
        } else if (prediction?.result === 'safe') {
            stats.safeVisited++;
            await updateIcon(tabId, 'safe');
            chrome.action.setBadgeText({ text: "", tabId });
        }
        
        // Save stats periodically
        chrome.storage.local.set({ stats });
    }
});

// --- Message Handler ---
chrome.runtime.onMessage.addListener((request, sender, sendResponse) => {
    if (request.action === "checkCurrentTab") {
        predict(request.url).then(res => {
            sendResponse(res || { result: 'error', reason: 'no_response' });
        }).catch(err => {
            sendResponse({ result: 'error', reason: 'exception', error: err.message });
        });
        return true;
    }
    
    if (request.action === "addToWhitelist") {
        try {
            const hostname = new URL(request.url).hostname.replace(/^www\./, '');
            whitelist.add(hostname);
            chrome.storage.local.set({ whitelist: Array.from(whitelist) });
            sendResponse({ success: true, hostname });
        } catch { 
            sendResponse({ success: false }); 
        }
        return true;
    }
    
    if (request.action === "removeFromWhitelist") {
        try {
            const hostname = request.hostname;
            whitelist.delete(hostname);
            chrome.storage.local.set({ whitelist: Array.from(whitelist) });
            sendResponse({ success: true });
        } catch { 
            sendResponse({ success: false }); 
        }
        return true;
    }
    
    if (request.action === "getStats") {
        sendResponse(stats);
        return true;
    }
    
    if (request.action === "getWhitelist") {
        sendResponse(Array.from(whitelist));
        return true;
    }
});
