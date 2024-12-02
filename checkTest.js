const crypto = require('crypto');
const { encrypt, decrypt, generateSubstitutionMatrix } = require('./OptimizedauraProtocol');

function aesEncrypt(plaintext, key) {
    const iv = crypto.randomBytes(16);
    const cipher = crypto.createCipheriv('aes-256-cbc', key, iv);
    let encrypted = cipher.update(plaintext, 'utf8', 'hex');
    encrypted += cipher.final('hex');
    return iv.toString('hex') + encrypted;
}

function aesDecrypt(ciphertext, key) {
    const iv = Buffer.from(ciphertext.slice(0, 32), 'hex');
    const encryptedText = ciphertext.slice(32);
    const decipher = crypto.createDecipheriv('aes-256-cbc', key, iv);
    let decrypted = decipher.update(encryptedText, 'hex', 'utf8');
    decrypted += decipher.final('utf8');
    return decrypted;
}

function tripleDesEncrypt(plaintext, key) {
    const iv = crypto.randomBytes(8);
    const cipher = crypto.createCipheriv('des-ede3-cbc', key, iv);
    let encrypted = cipher.update(plaintext, 'utf8', 'hex');
    encrypted += cipher.final('hex');
    return iv.toString('hex') + encrypted;
}

function tripleDesDecrypt(ciphertext, key) {
    const iv = Buffer.from(ciphertext.slice(0, 16), 'hex');
    const encryptedText = ciphertext.slice(16);
    const decipher = crypto.createDecipheriv('des-ede3-cbc', key, iv);
    let decrypted = decipher.update(encryptedText, 'hex', 'utf8');
    decrypted += decipher.final('utf8');
    return decrypted;
}

function calculateEntropy(text) {
    const freq = {};
    for (let char of text) {
        freq[char] = (freq[char] || 0) + 1;
    }
    return Object.values(freq).reduce((entropy, count) => {
        const p = count / text.length;
        return entropy - p * Math.log2(p);
    }, 0);
}

function calculateAvalancheEffect(plaintext, ciphertext, encryptFunc, key) {
    let totalBitChanges = 0;
    const originalCiphertext = ciphertext;
    
    for (let i = 0; i < plaintext.length; i++) {
        const modifiedPlaintext = plaintext.substring(0, i) + 
            String.fromCharCode(plaintext.charCodeAt(i) ^ 1) + 
            plaintext.substring(i + 1);
        const modifiedCiphertext = encryptFunc(modifiedPlaintext, key);
        
        totalBitChanges += [...originalCiphertext].reduce((changes, char, index) => 
            changes + (char.charCodeAt(0) ^ modifiedCiphertext.charCodeAt(index)).toString(2)
                .split('').filter(bit => bit === '1').length, 0);
    }
    
    return (totalBitChanges / (plaintext.length * 8 * originalCiphertext.length)) * 100;
}

async function runComparison(iterations = 1000) {
    const auraKey = "testkey123";
    const aesKey = crypto.randomBytes(32);
    const tripleDesKey = crypto.randomBytes(24);
    const auraMatrix = generateSubstitutionMatrix(auraKey);

    const results = {
        aura: { encryptionTime: 0, decryptionTime: 0, encryptionMemory: 0, decryptionMemory: 0, entropy: 0, avalancheEffect: 0, throughput: 0 },
        aes: { encryptionTime: 0, decryptionTime: 0, encryptionMemory: 0, decryptionMemory: 0, entropy: 0, avalancheEffect: 0, throughput: 0 },
        tripleDes: { encryptionTime: 0, decryptionTime: 0, encryptionMemory: 0, decryptionMemory: 0, entropy: 0, avalancheEffect: 0, throughput: 0 }
    };

    for (let i = 0; i < iterations; i++) {
        const plaintext = crypto.randomBytes(32).toString('hex');

        // Aura Protocol
        let startMemory = process.memoryUsage().heapUsed;
        let startTime = process.hrtime();
        const auraCiphertext = encrypt(plaintext, auraKey, auraMatrix);
        let endTime = process.hrtime(startTime);
        let endMemory = process.memoryUsage().heapUsed;
        results.aura.encryptionTime += endTime[0] * 1e3 + endTime[1] / 1e6;
        results.aura.encryptionMemory += Math.max(0, endMemory - startMemory) / 1024;
        results.aura.entropy += calculateEntropy(auraCiphertext);
        results.aura.avalancheEffect += calculateAvalancheEffect(plaintext, auraCiphertext, (pt, key) => encrypt(pt, key, auraMatrix), auraKey);
        results.aura.throughput += (plaintext.length * 8) / ((endTime[0] * 1e9 + endTime[1]) / 1e9);

        startMemory = process.memoryUsage().heapUsed;
        startTime = process.hrtime();
        decrypt(auraCiphertext, auraKey, auraMatrix);
        endTime = process.hrtime(startTime);
        endMemory = process.memoryUsage().heapUsed;
        results.aura.decryptionTime += endTime[0] * 1e3 + endTime[1] / 1e6;
        results.aura.decryptionMemory += Math.max(0, endMemory - startMemory) / 1024;

        // AES
        startMemory = process.memoryUsage().heapUsed;
        startTime = process.hrtime();
        const aesCiphertext = aesEncrypt(plaintext, aesKey);
        endTime = process.hrtime(startTime);
        endMemory = process.memoryUsage().heapUsed;
        results.aes.encryptionTime += endTime[0] * 1e3 + endTime[1] / 1e6;
        results.aes.encryptionMemory += Math.max(0, endMemory - startMemory) / 1024;
        results.aes.entropy += calculateEntropy(aesCiphertext);
        results.aes.avalancheEffect += calculateAvalancheEffect(plaintext, aesCiphertext, aesEncrypt, aesKey);
        results.aes.throughput += (plaintext.length * 8) / ((endTime[0] * 1e9 + endTime[1]) / 1e9);

        startMemory = process.memoryUsage().heapUsed;
        startTime = process.hrtime();
        aesDecrypt(aesCiphertext, aesKey);
        endTime = process.hrtime(startTime);
        endMemory = process.memoryUsage().heapUsed;
        results.aes.decryptionTime += endTime[0] * 1e3 + endTime[1] / 1e6;
        results.aes.decryptionMemory += Math.max(0, endMemory - startMemory) / 1024;

        // Triple DES
        startMemory = process.memoryUsage().heapUsed;
        startTime = process.hrtime();
        const tripleDesCiphertext = tripleDesEncrypt(plaintext, tripleDesKey);
        endTime = process.hrtime(startTime);
        endMemory = process.memoryUsage().heapUsed;
        results.tripleDes.encryptionTime += endTime[0] * 1e3 + endTime[1] / 1e6;
        results.tripleDes.encryptionMemory += Math.max(0, endMemory - startMemory) / 1024;
        results.tripleDes.entropy += calculateEntropy(tripleDesCiphertext);
        results.tripleDes.avalancheEffect += calculateAvalancheEffect(plaintext, tripleDesCiphertext, tripleDesEncrypt, tripleDesKey);
        results.tripleDes.throughput += (plaintext.length * 8) / ((endTime[0] * 1e9 + endTime[1]) / 1e9);

        startMemory = process.memoryUsage().heapUsed;
        startTime = process.hrtime();
        tripleDesDecrypt(tripleDesCiphertext, tripleDesKey);
        endTime = process.hrtime(startTime);
        endMemory = process.memoryUsage().heapUsed;
        results.tripleDes.decryptionTime += endTime[0] * 1e3 + endTime[1] / 1e6;
        results.tripleDes.decryptionMemory += Math.max(0, endMemory - startMemory) / 1024;
    }

    // Calculate averages
    for (let algo in results) {
        for (let metric in results[algo]) {
            results[algo][metric] /= iterations;
        }
    }

    return results;
}

runComparison().then(results => {
    console.log("Comparison Results (1000 iterations):");
    for (let algo in results) {
        console.log(`\n${algo.toUpperCase()}:`);
        console.log(`Avg Encryption Time: ${results[algo].encryptionTime.toFixed(2)} ms`);
        console.log(`Avg Decryption Time: ${results[algo].decryptionTime.toFixed(2)} ms`);
        console.log(`Avg Encryption Memory: ${results[algo].encryptionMemory.toFixed(2)} KB`);
        console.log(`Avg Decryption Memory: ${results[algo].decryptionMemory.toFixed(2)} KB`);
        console.log(`Avg Entropy: ${results[algo].entropy.toFixed(4)} bits`);
        console.log(`Avg Avalanche Effect: ${results[algo].avalancheEffect.toFixed(2)}%`);
        console.log(`Avg Throughput: ${results[algo].throughput.toFixed(2)} bits/sec`);
    }
}).catch(error => {
    console.error("An error occurred during comparison:", error);
});