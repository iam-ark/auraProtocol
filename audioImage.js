const elliptic = require('elliptic');
const fs = require('fs');
const auraProtocol = require('./OptimizedauraProtocol.js');

// Define substitutionMatrix
const substitutionMatrix = auraProtocol.generateSubstitutionMatrix('ark');

// Create a new elliptic curve object (for example, secp256k1 curve used in Bitcoin)
const curve = elliptic.ec('secp256k1');

// Alice generates her key pair
const aliceKeyPair = curve.genKeyPair();

// Bob generates his key pair
const bobKeyPair = curve.genKeyPair();

// Alice computes the shared secret using her private key and Bob's public key
const aliceSharedSecret = aliceKeyPair.derive(bobKeyPair.getPublic()).toString('hex');

// Bob computes the shared secret using his private key and Alice's public key
const bobSharedSecret = bobKeyPair.derive(aliceKeyPair.getPublic()).toString('hex');

// Function to encrypt text data using auraProtocol with UTF-8 encoding
function encryptText(text, sharedSecret, substitutionMatrix) {
  const hexEncodedText = Buffer.from(text, 'utf8').toString('hex');
  return auraProtocol.encrypt(hexEncodedText, sharedSecret, substitutionMatrix);
}

// Function to decrypt text data using auraProtocol with UTF-8 encoding
function decryptText(encryptedText, sharedSecret, substitutionMatrix) {
  const decryptedHexEncodedText = auraProtocol.decrypt(encryptedText, sharedSecret, substitutionMatrix);
  return Buffer.from(decryptedHexEncodedText, 'hex').toString('utf8');
}

// Function to encrypt image data using auraProtocol
function encryptImage(imageData, sharedSecret, substitutionMatrix) {
  const base64Image = imageData.toString('base64');
  return auraProtocol.encrypt(base64Image, sharedSecret, substitutionMatrix);
}

// Function to decrypt image data using auraProtocol
function decryptImage(encryptedImageData, sharedSecret, substitutionMatrix) {
  const decryptedBase64Image = auraProtocol.decrypt(encryptedImageData, sharedSecret, substitutionMatrix);
  return Buffer.from(decryptedBase64Image, 'base64');
}

// Function to encrypt audio data using auraProtocol
function encryptAudio(audioData, sharedSecret, substitutionMatrix) {
  const base64Audio = audioData.toString('base64');
  return auraProtocol.encrypt(base64Audio, sharedSecret, substitutionMatrix);
}

// Function to decrypt audio data using auraProtocol
function decryptAudio(encryptedAudioData, sharedSecret, substitutionMatrix) {
  const decryptedBase64Audio = auraProtocol.decrypt(encryptedAudioData, sharedSecret, substitutionMatrix);
  return Buffer.from(decryptedBase64Audio, 'base64');
}


// Example usage
const textData = "Abdul Rahman Khan 054";
const encryptedText = encryptText(textData, bobSharedSecret, substitutionMatrix);
console.log('Encrypted text:', encryptedText);
const decryptedText = decryptText(encryptedText, aliceSharedSecret, substitutionMatrix);
console.log('Decrypted text:', decryptedText);

// Write encrypted text to a file
fs.writeFileSync('encryptedText.txt', encryptedText, 'utf8');

// Read image file
const imageData = fs.readFileSync('./AuraWritten.png');

// Encrypt image data
const encryptedImageData = encryptImage(imageData, bobSharedSecret, substitutionMatrix);
fs.writeFileSync('encryptedImage.txt', encryptedImageData, 'utf8');

// Decrypt image data
const decryptedImageData = decryptImage(encryptedImageData, aliceSharedSecret, substitutionMatrix);
fs.writeFileSync('decryptedImage.png', decryptedImageData);

// Read audio file
const audioData = fs.readFileSync('./audioCheck.mp3');

// Encrypt audio data
const encryptedAudioData = encryptAudio(audioData, bobSharedSecret, substitutionMatrix);
fs.writeFileSync('encryptedAudio.txt', encryptedAudioData, 'utf8');

// Decrypt audio data
const decryptedAudioData = decryptAudio(encryptedAudioData, aliceSharedSecret, substitutionMatrix);
fs.writeFileSync('decryptedAudio.mp3', decryptedAudioData);
