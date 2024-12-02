const crypto = require('crypto');
const { encrypt, decrypt, generateSubstitutionMatrix } = require('./OptimizedauraProtocol');

function testEncryptionDecryption(plaintext, key, testName) {
    const matrix = generateSubstitutionMatrix(key);
    const ciphertext = encrypt(plaintext, key, matrix);
    const decryptedText = decrypt(ciphertext, key, matrix);
    
    const result = plaintext === decryptedText ? "Success" : "Failure";
    console.log(`${testName}: ${result}`);
    if (result === "Failure") {
        console.log(`  Original: ${plaintext}`);
        console.log(`  Decrypted: ${decryptedText}`);
    }
    return result === "Success";
}

function generateRandomString(length) {
    return crypto.randomBytes(Math.ceil(length/2))
        .toString('hex')
        .slice(0, length);
}

function runTests() {
    const testCases = [
        { name: "Empty string", text: "" },
        { name: "Single character", text: "a" },
        { name: "Alphanumeric", text: "abc123XYZ" },
        { name: "Special characters", text: "!@#$%^&*()_+-=[]{}|;:,.<>?" },
        { name: "Unicode characters", text: "こんにちは世界 你好世界 Hello World Здравствуй, мир" },
        { name: "Very long string", text: "a".repeat(10000) },
        { name: "Long random string", text: generateRandomString(10000) },
        { name: "Repeated pattern", text: "abcabcabc".repeat(1000) },
        { name: "All spaces", text: " ".repeat(100) },
        { name: "Mixed spaces and tabs", text: "  \t  \t\t    \t  ".repeat(50) },
        { name: "Newlines and carriage returns", text: "Line1\nLine2\rLine3\r\nLine4" },
        { name: "JSON structure", text: JSON.stringify({ key: "value", nested: { array: [1,2,3] } }) },
        { name: "Base64 encoded", text: Buffer.from("Hello World").toString('base64') },
        { name: "HTML content", text: "<html><body><h1>Hello World</h1><p>This is a test</p></body></html>" },
        { name: "SQL query", text: "SELECT * FROM users WHERE username = 'admin' AND password = 'password'" },
        { name: "Binary data", text: Buffer.from([0xFF, 0x00, 0xAA, 0x55, 0x12, 0x34]).toString() },
        { name: "Emoji string", text: "🌈🌟🎉🎊🎁🎂🍕🍔🍟🍗" },
        { name: "Mixed case", text: "AbCdEfGhIjKlMnOpQrStUvWxYz" },
        { name: "Palindrome", text: "A man a plan a canal Panama".repeat(100) },
        { name: "Alternating case", text: "AlTeRnAtInG cAsE".repeat(500) },
    ];

    const keys = [
        "shortkey",
        "averagelengthkey12345",
        "ThisIsAVeryLongKeyThatMightCauseIssuesIfNotHandledProperly123456789",
        "🔑🗝️", // emoji key
        " ", // single space
        "\t\n\r", // whitespace characters
        "a".repeat(1000), // very long single character key
        generateRandomString(100), // random string key
    ];

    let totalTests = 0;
    let passedTests = 0;

    for (const key of keys) {
        console.log(`\nTesting with key: ${key.length > 50 ? key.slice(0, 50) + '...' : key}`);
        for (const testCase of testCases) {
            totalTests++;
            if (testEncryptionDecryption(testCase.text, key, testCase.name)) {
                passedTests++;
            }
        }
    }

    console.log(`\nTest Summary: ${passedTests}/${totalTests} tests passed`);
}

runTests();