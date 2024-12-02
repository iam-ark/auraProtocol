const { encrypt: customEncrypt, decrypt: customDecrypt, generateSubstitutionMatrix } = require('./OptimizedauraProtocol');
const crypto = require('crypto');

// AES encryption/decryption functions
function aesEncrypt(text, key) {
    if (Buffer.byteLength(key, 'hex') !== 32) {
        throw new Error('Invalid AES key length. Key must be 256 bits (32 bytes).');
    }
    
    const iv = crypto.randomBytes(16);
    const cipher = crypto.createCipheriv('aes-256-cbc', Buffer.from(key, 'hex'), iv);
    let encrypted = cipher.update(text, 'utf8');
    encrypted = Buffer.concat([encrypted, cipher.final()]);
    return iv.toString('hex') + ':' + encrypted.toString('hex');
}

function aesDecrypt(text, key) {
    if (Buffer.byteLength(key, 'hex') !== 32) {
        throw new Error('Invalid AES key length. Key must be 256 bits (32 bytes).');
    }

    const textParts = text.split(':');
    const iv = Buffer.from(textParts.shift(), 'hex');
    const encryptedText = Buffer.from(textParts.join(':'), 'hex');
    const decipher = crypto.createDecipheriv('aes-256-cbc', Buffer.from(key, 'hex'), iv);
    let decrypted = decipher.update(encryptedText);
    decrypted = Buffer.concat([decrypted, decipher.final()]);
    return decrypted.toString('utf8');
}

// Known-Plaintext Attack (KPA) function
function performKPA(plainTexts, key, algorithm) {
    const pairs = plainTexts.map(plainText => {
        let encryptedText;
        if (algorithm === 'custom') {
            const substitutionMatrix = generateSubstitutionMatrix(key);
            encryptedText = customEncrypt(plainText, key, substitutionMatrix);
        } else if (algorithm === 'aes') {
            encryptedText = aesEncrypt(plainText, key);
        } else {
            throw new Error('Unsupported algorithm');
        }
        return { plainText, encryptedText };
    });

    console.log(`\n${algorithm.toUpperCase()} Pairs:`);
    pairs.forEach(pair => {
        console.log(`Plaintext: ${pair.plainText}, Ciphertext: ${pair.encryptedText}`);
    });

    // Analyze pairs to attempt key recovery
    const possibleKeys = analyzePairs(pairs, algorithm);
    return possibleKeys;
}

// Detailed analysis function
function analyzePairs(pairs, algorithm) {
    const keyCandidates = [];
    const pairCount = pairs.length;

    // Analyzing pair-wise differences to detect patterns
    for (let i = 0; i < pairCount - 1; i++) {
        const currentPair = pairs[i];
        const nextPair = pairs[i + 1];

        const plainDiff = xorHex(currentPair.plainText, nextPair.plainText);
        const cipherDiff = xorHex(currentPair.encryptedText, nextPair.encryptedText);

        console.log(`\nDifference Analysis (Pair ${i} and ${i + 1}):`);
        console.log(`Plaintext Difference: ${plainDiff}`);
        console.log(`Ciphertext Difference: ${cipherDiff}`);

        // Based on the difference, try to infer part of the key or analyze the substitution matrix
        let inferredKeyPart;
        if (algorithm === 'custom') {
            inferredKeyPart = inferKeyPartCustom(plainDiff, cipherDiff);
        } else if (algorithm === 'aes') {
            inferredKeyPart = inferKeyPartAES(plainDiff, cipherDiff);
        }

        if (inferredKeyPart) {
            keyCandidates.push(inferredKeyPart);
        }
    }

    return keyCandidates.length > 0 ? keyCandidates : ['Could not determine the key'];
}

// Utility function to XOR two hex strings
function xorHex(hex1, hex2) {
    const result = [];
    for (let i = 0; i < hex1.length && i < hex2.length; i += 2) {
        result.push((parseInt(hex1.substr(i, 2), 16) ^ parseInt(hex2.substr(i, 2), 16)).toString(16).padStart(2, '0'));
    }
    return result.join('');
}

// Function to infer part of the key for custom algorithm
function inferKeyPartCustom(plainDiff, cipherDiff) {
    console.log(`\nCustom Algorithm Key Inference:`);
    
    const plainDiffBinary = hexToBinary(plainDiff);
    const cipherDiffBinary = hexToBinary(cipherDiff);
    
    const potentialKeyParts = [];
    
    for (let i = 0; i < plainDiffBinary.length; i++) {
        if (plainDiffBinary[i] !== cipherDiffBinary[i]) {
            potentialKeyParts.push(`Bit difference at position ${i}`);
        }
    }

    if (potentialKeyParts.length > 0) {
        console.log(`Possible keys for custom algorithm: ${potentialKeyParts.join(', ')}`);
    }
    
    return potentialKeyParts.length > 0 ? potentialKeyParts.join(', ') : null;
}

// Function to infer part of the key for AES
function inferKeyPartAES(plainDiff, cipherDiff) {
    console.log(`\nAES Key Inference:`);
    
    const plainDiffBinary = hexToBinary(plainDiff);
    const cipherDiffBinary = hexToBinary(cipherDiff);
    
    const potentialKeyParts = [];
    
    for (let i = 0; i < plainDiffBinary.length; i++) {
        if (plainDiffBinary[i] !== cipherDiffBinary[i]) {
            potentialKeyParts.push(`Bit difference at position ${i}`);
        }
    }

    if (potentialKeyParts.length > 0) {
        console.log(`Possible keys for AES: ${potentialKeyParts.join(', ')}`);
    }
    
    return potentialKeyParts.length > 0 ? potentialKeyParts.join(', ') : null;
}

// Utility function to convert hex string to binary string
function hexToBinary(hex) {
    return hex.match(/.{1,2}/g).map(hexChar => {
        return parseInt(hexChar, 16).toString(2).padStart(8, '0');
    }).join('');
}

// Example usage
const key = '0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef'; // Example 256-bit key (hexadecimal)
const plainTexts = [
    'Hello, world!',
    'This is a test.',
    'Known-plaintext attack.',
    'Another example.',
];

const customPossibleKeys = performKPA(plainTexts, key, 'custom');
const aesPossibleKeys = performKPA(plainTexts, key, 'aes');

console.log(`\nPossible keys for custom algorithm: ${customPossibleKeys.join(', ')}`);
console.log(`Possible keys for AES: ${aesPossibleKeys.join(', ')}`);
