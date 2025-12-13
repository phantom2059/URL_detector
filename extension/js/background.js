// Background Service Worker

importScripts('../lib/onnxruntime-web.min.js');
importScripts('feature_extractor.js');

// Configure ONNX Runtime to use the local WASM files and disable dynamic import if possible
ort.env.wasm.wasmPaths = {
    'ort-wasm.wasm': '../lib/ort-wasm.wasm',
    'ort-wasm-simd.wasm': '../lib/ort-wasm-simd.wasm'
};
// Disable multi-threading in Service Worker environment to avoid "import() disallowed" issues
ort.env.wasm.numThreads = 1;

const MODEL_PATH = '../model/model.onnx';
const BLACKLIST_PATH = '../assets/phishurl-list.csv';
const SAFELIST_PATH = '../assets/safe-domains.json';

let session = null;
let featureExtractor = new FeatureExtractor();
let whitelist = new Set(); // User whitelist
let globalSafeList = new Set(); // Pre-defined safe domains
let blacklist = new Set(); 

// --- Initialization ---
async function initModel() {
    try {
        console.log("Loading ONNX model from:", MODEL_PATH);
        // Ensure WASM backend is used
        const options = { executionProviders: ['wasm'] };
        session = await ort.InferenceSession.create(MODEL_PATH, options);
        console.log("Model loaded successfully. Input names:", session.inputNames, "Output names:", session.outputNames);
    } catch (e) {
        console.error("Failed to load model:", e);
        session = null;
    }
}

async function loadLists() {
    // Load whitelist from storage
    const stored = await chrome.storage.local.get(['whitelist']);
    if (stored.whitelist) {
        whitelist = new Set(stored.whitelist);
        console.log(`Loaded ${whitelist.size} entries into user whitelist.`);
    }

    // Load Global Safe List
    try {
        const response = await fetch(SAFELIST_PATH);
        if (response.ok) {
            const domains = await response.json();
            domains.forEach(d => globalSafeList.add(d));
            console.log(`Loaded ${globalSafeList.size} entries into global safe list.`);
        }
    } catch (e) {
        console.error("Failed to load global safe list:", e);
    }
    
    // Load blacklist from CSV
    try {
        console.log("Loading blacklist from:", BLACKLIST_PATH);
        const response = await fetch(BLACKLIST_PATH);
        if (!response.ok) {
            throw new Error(`HTTP ${response.status}: ${response.statusText}`);
        }
        const text = await response.text();
        const lines = text.split('\n');
        // Optimized CSV parser: our optimized blacklist has only URLs (one per line, no header)
        for (let i = 0; i < lines.length; i++) {
            const line = lines[i].trim();
            if (!line) continue;
            
            // Our optimized format: just URL, one per line
            const cleanUrl = line.replace(/^"|"$/g, '').trim();
            if (cleanUrl && (cleanUrl.includes('http') || cleanUrl.includes('www') || cleanUrl.includes('.'))) {
                try {
                    const urlObj = new URL(cleanUrl.startsWith('http') ? cleanUrl : `https://${cleanUrl}`);
                    const hostname = urlObj.hostname;
                    blacklist.add(cleanUrl); // Add full URL
                    blacklist.add(hostname); // Add hostname too for broader match
                } catch(e) {
                    // If URL parsing fails, just add as-is (might be domain only)
                    blacklist.add(cleanUrl);
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

    // 1. User Whitelist Check
    if (whitelist.has(urlHostname)) {
        return { result: 'safe', reason: 'whitelist', score: 0.0 };
    }

    // 2. Global Safe List Check
    // Check main domain and subdomains
    if (globalSafeList.has(urlHostname)) {
         return { result: 'safe', reason: 'global_safe', score: 0.0 };
    }
    // Check if hostname ends with any safe domain (e.g. "mail.google.com" ends with "google.com")
    for (const safeDomain of globalSafeList) {
        if (urlHostname.endsWith('.' + safeDomain) || urlHostname === safeDomain) {
            return { result: 'safe', reason: 'global_safe', score: 0.0 };
        }
    }

    // 3. Blacklist Check
    if (blacklist.has(urlStr) || blacklist.has(urlHostname)) {
        return { result: 'phishing', score: 1.0, reason: 'blacklist' };
    }

    if (!session) {
        console.warn("Model not loaded yet, returning null");
        return { result: 'error', reason: 'model_not_loaded' };
    }

    // 4. ML Check
    try {
        const inputVector = featureExtractor.getVector(urlStr);
        if (!inputVector) {
            console.warn("Failed to extract features from URL");
            return { result: 'error', reason: 'feature_extraction_failed' };
        }

        // Create ONNX tensor
        // Ensure data is Float32Array for performance and type safety
        const floatData = new Float32Array(inputVector);
        const tensor = new ort.Tensor('float32', floatData, [1, inputVector.length]);
        
        const feeds = { 'features': tensor }; 
        
        // CatBoost ONNX 'probabilities' output can sometimes be a Sequence of Maps, 
        // which causes "Can't access output tensor data" in ORT Web WASM backend.
        // We try to fetch everything first. If it fails, we fall back to fetching only 'label'.
        let results;
        try {
            results = await session.run(feeds);
        } catch (runError) {
            console.warn("Standard session.run failed, trying to fetch only 'label'...", runError);
            try {
                // Try fetching only label. This often bypasses the Sequence output issue.
                results = await session.run(feeds, ['label']);
            } catch (retryError) {
                console.error("Retry with only 'label' failed:", retryError);
                throw retryError;
            }
        }
        
        // Debug outputs
        // console.log("Model results keys:", Object.keys(results));

        let label = 0;
        let phishProb = 0; // Default if we can't get probability

        // Extract Label
        if (results.label) {
            // 'label' is usually an Int64 tensor. data is BigInt64Array or similar.
            // Accessing [0] works.
            label = Number(results.label.data[0]);
        } else if (results.labels) {
             label = Number(results.labels.data[0]);
        }
        
        // Extract Probability
        if (results.probabilities) {
            const data = results.probabilities.data;
            if (data.length >= 2) {
                phishProb = data[1];
            } else if (data.length === 1) {
                phishProb = data[0];
            }
        } else {
             // If we only fetched label (fallback case), we set prob based on label
             // 0 -> 0.0 (safe), 1 -> 1.0 (phishing)
             phishProb = label === 1 ? 0.99 : 0.01;
        }

        console.log(`Prediction: Label=${label}, Prob=${phishProb}`);

        if (label === 1 || phishProb > 0.5) {
            return { result: 'phishing', score: phishProb, reason: 'ml' };
        }
        return { result: 'safe', score: phishProb, reason: 'ml' };

    } catch (e) {
        console.error("Prediction error:", e);
        return { result: 'error', reason: 'prediction_failed', error: e.message };
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
        predict(request.url).then(res => {
            sendResponse(res || { result: 'error', reason: 'no_response' });
        }).catch(err => {
            console.error("Error in checkCurrentTab:", err);
            sendResponse({ result: 'error', reason: 'exception', error: err.message });
        });
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
