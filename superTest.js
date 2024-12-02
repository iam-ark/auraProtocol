const CryptoJS = require('crypto-js');
const { performance } = require('perf_hooks');
const { encrypt: customEncrypt, decrypt: customDecrypt, generateSubstitutionMatrix } = require('./OptimizedauraProtocol');

// Function to perform AES encryption
function aesEncrypt(text, key) {
    const cipher = CryptoJS.AES.encrypt(text, key);
    return cipher.toString();
}

// Function to perform AES decryption
function aesDecrypt(cipherText, key) {
    const bytes = CryptoJS.AES.decrypt(cipherText, key);
    return bytes.toString(CryptoJS.enc.Utf8);
}

// Function to perform DES encryption
function desEncrypt(text, key) {
    const iv = CryptoJS.enc.Utf8.parse('12345678');
    const encrypted = CryptoJS.DES.encrypt(text, key, { iv: iv });
    return encrypted.toString();
}

// Function to perform DES decryption
function desDecrypt(cipherText, key) {
    const iv = CryptoJS.enc.Utf8.parse('12345678');
    const decrypted = CryptoJS.DES.decrypt(cipherText, key, { iv: iv });
    return decrypted.toString(CryptoJS.enc.Utf8);
}

// Function to run benchmarks and calculate averages
function runBenchmark(algorithmName, encryptFunc, decryptFunc, iterations, key, substitutionMatrix = null) {
    let totalEncryptTime = 0;
    let totalDecryptTime = 0;
    let totalEncryptMemory = 0;
    let totalDecryptMemory = 0;
    let totalLatency = 0;
    let totalEnergyConsumption = 0;
    let totalAvalancheEffect = 0;
    let totalEntropy = 0;

    const plaintext = 'Hello, this is a test message!';
    const dataSize = Buffer.byteLength(plaintext, 'utf8');

    for (let i = 0; i < iterations; i++) {
        // Measure encryption time and memory usage
        const startEncrypt = performance.now();
        const encrypted = substitutionMatrix ? encryptFunc(plaintext, key, substitutionMatrix) : encryptFunc(plaintext, key);
        const endEncrypt = performance.now();
        const encryptTime = endEncrypt - startEncrypt;
        const encryptMemoryUsage = process.memoryUsage().heapUsed;

        // Measure decryption time and memory usage
        const startDecrypt = performance.now();
        const decrypted = substitutionMatrix ? decryptFunc(encrypted, key, substitutionMatrix) : decryptFunc(encrypted, key);
        const endDecrypt = performance.now();
        const decryptTime = endDecrypt - startDecrypt;
        const decryptMemoryUsage = process.memoryUsage().heapUsed;

        // Calculate latency (clocks per cycle)
        const latency = (encryptTime + decryptTime) / 2; // Average latency per cycle
        totalLatency += latency;

        // Calculate energy consumption
        const energyConsumption = latency; // Simplified example, should correlate with actual energy model
        totalEnergyConsumption += energyConsumption;

        // Calculate avalanche effect (assuming a measure of how output changes with input changes)
        const avalancheEffect = calculateAvalancheEffect(plaintext, key, encryptFunc);
        totalAvalancheEffect += avalancheEffect;

        // Calculate entropy of cipher text
        const entropy = calculateEntropy(encrypted);
        totalEntropy += entropy;

        // Accumulate total times and memory
        totalEncryptTime += encryptTime;
        totalDecryptTime += decryptTime;
        totalEncryptMemory += encryptMemoryUsage;
        totalDecryptMemory += decryptMemoryUsage;

        // Optional: Verify decryption result for correctness
        if (decrypted !== plaintext) {
            console.error(`Decryption error for ${algorithmName}`);
        }
    }

    // Calculate averages
    const avgEncryptTime = totalEncryptTime / iterations;
    const avgDecryptTime = totalDecryptTime / iterations;
    const avgEncryptMemory = totalEncryptMemory / iterations;
    const avgDecryptMemory = totalDecryptMemory / iterations;
    const avgLatency = totalLatency / iterations;
    const avgEnergyConsumption = totalEnergyConsumption / iterations;
    const avgAvalancheEffect = totalAvalancheEffect / iterations;
    const avgEntropy = totalEntropy / iterations;

    // Calculate throughput
    const encryptThroughput = (dataSize / (avgEncryptTime / 1000)).toFixed(2); // Bytes per second
    const decryptThroughput = (dataSize / (avgDecryptTime / 1000)).toFixed(2); // Bytes per second

    // Display results
    console.log(`\n----- ${algorithmName} -----`);
    console.log(`Average Encryption Time: ${avgEncryptTime.toFixed(2)} milliseconds`);
    console.log(`Average Decryption Time: ${avgDecryptTime.toFixed(2)} milliseconds`);
    console.log(`Average Encryption Memory Usage: ${(avgEncryptMemory / 1024).toFixed(2)} KB`);
    console.log(`Average Decryption Memory Usage: ${(avgDecryptMemory / 1024).toFixed(2)} KB`);
    console.log(`Average Latency (Clocks per Cycle): ${avgLatency.toFixed(2)}`);
    console.log(`Average Energy Consumption: ${avgEnergyConsumption.toFixed(2)}`);
    console.log(`Average Avalanche Effect: ${avgAvalancheEffect.toFixed(2)}`);
    console.log(`Average Entropy of Cipher Text: ${avgEntropy.toFixed(2)}`);
    console.log(`Encryption Throughput: ${encryptThroughput} Bytes/second`);
    console.log(`Decryption Throughput: ${decryptThroughput} Bytes/second`);
}

// Function to calculate avalanche effect (example, replace with actual implementation)
function calculateAvalancheEffect(plaintext, key, encryptFunc) {
    const encrypted1 = encryptFunc(plaintext, key);
    const encrypted2 = encryptFunc(plaintext.substring(0, plaintext.length - 1), key);
    let count = 0;
    for (let i = 0; i < encrypted1.length; i++) {
        if (encrypted1[i] !== encrypted2[i]) {
            count++;
        }
    }
    return (count / encrypted1.length) * 100; // Percentage of changed bits
}

// Function to calculate entropy of cipher text
function calculateEntropy(cipherText) {
    let hexString;

    // Check if cipherText is already in hex format
    if (typeof cipherText === 'string' && /^[0-9A-Fa-f]+$/g.test(cipherText)) {
        hexString = cipherText; // Already hex, use as is
    } else {
        // Convert cipherText to hex format
        hexString = CryptoJS.enc.Hex.stringify(CryptoJS.enc.Utf8.parse(cipherText));
    }

    // Calculate entropy of the hex string
    let entropy = 0;
    const charCount = new Map();

    for (let char of hexString) {
        charCount.set(char, (charCount.get(char) || 0) + 1);
    }

    const totalCount = hexString.length;

    charCount.forEach(count => {
        const probability = count / totalCount;
        entropy -= probability * Math.log2(probability);
    });

    return entropy;
}

// Main function to compare different encryption algorithms
function compareAlgorithms(iterations) {
    const key = 'mysecretkey12345'; // Example key
    const substitutionMatrix = generateSubstitutionMatrix(key);

    // List of algorithms to compare
    const algorithms = [
        { name: 'aura Protocol', encrypt: (text, key) => customEncrypt(text, key, substitutionMatrix), decrypt: (cipherText, key) => customDecrypt(cipherText, key, substitutionMatrix) },
        { name: 'AES', encrypt: aesEncrypt, decrypt: aesDecrypt },
        { name: 'DES', encrypt: desEncrypt, decrypt: desDecrypt }
        // Add more algorithms as needed
    ];

    algorithms.forEach(algorithm => {
        runBenchmark(algorithm.name, algorithm.encrypt, algorithm.decrypt, iterations, key, substitutionMatrix);
    });
}

// Run comparison with 1000 iterations per algorithm
const iterations = 1000;
for (let i = 1; i <= 5; i++) {
    console.log(`\nSet No. ${i}`);
    compareAlgorithms(iterations);
}
