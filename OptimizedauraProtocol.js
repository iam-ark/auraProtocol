const CryptoJS = require('crypto-js');
const seedrandom = require('seedrandom');
// console.log("Cipher text: ",encrypt("The quick brown fox jumps over the lazy dog! 🦊🐶¡Hola, ¿cómo estás?","ark",generateSubstitutionMatrix("ark")));
// console.log("Plain text: ",decrypt("5fa2f0fd723cf98fbad7fcd9452dfeb0875cddc96d39fddda477b4e56629623e89648f89b5767815afd7e0043b239588ade9e1a6e30beec9dcd9db38173d5bfca6af78e1190efb7ca330058685d42b1c","ark",generateSubstitutionMatrix("ark")));
// console.log("Cipher text: ",encrypt("Hello World","ark",generateSubstitutionMatrix("ark")));
// Encryption function
function encrypt(plaintext, key, substitutionMatrix) {
    // SHA256 hashing of the key
    const hashedMessage = CryptoJS.SHA512(key).toString(CryptoJS.enc.Hex);
    
    const [part1, part2, part3, part4] = divideString(hashedMessage);

    // Convert part2 string to 4x4 matrix
    const part2_matrix = stringToMatrix(part2);
    const part3_matrix = stringToMatrix(part3);
    const part4_matrix = stringToMatrix(part4);
    // Convert plaintext to hexadecimal with PKCS#7 padding
    const hexRepresentation = textToHex(plaintext);

    // Divide padded hexadecimal string into 4x4 matrices
    const matrices = divideIntoMatrices(hexRepresentation);

    // Perform substitution on blocks
    const substitutedMatrices = performSubstitutionOnBlocks(matrices, substitutionMatrix);

    // XOR substituted matrix and part2 for intermediate cipher
    const xorResults = xorMatrices(part2_matrix, convertTo4x4Blocks(substitutedMatrices));

    const intString=matrixToString(xorResults);

    const pivot=adjacentXORs(intString);

    const intFinalString=cascadingXOR(part1,intString,pivot);

    const intMatrices=divideIntoMatrices(intFinalString);

    // Convert part1 into a 1x16 matrix and perform right shifts on substitutionMatrix
    const upSubMatrix = performRightShifts([...substitutionMatrix], hexStringToMatrix(part1));

    // Perform second substitution for final cipher
    const finalCipher = performSubstitutionOnBlocks(intMatrices, upSubMatrix);

    // Convert finalCipher matrix to string
    const resultString = matrixToString(finalCipher);

    const cipherString=cascadingXOR2(hashedMessage.substring(31,33), resultString);

    const fcipherString=xorFunction2(part1, cipherString);

    const mMatrices=moduloMatrices(part3_matrix,part4_matrix);

    const afcipherString = xorHexStrings(matrixToString(mMatrices),fcipherString);

    return afcipherString;

}

// Decryption function
function decrypt(cipherString, key, substitutionMatrix) {
    // SHA256 hashing of the key
    const hashedMessage = CryptoJS.SHA512(key).toString(CryptoJS.enc.Hex);

    const [part1, part2, part3, part4] = divideString(hashedMessage);

    const part3_matrix = stringToMatrix(part3);
    const part4_matrix = stringToMatrix(part4);

    const mMatrices=moduloMatrices(part3_matrix,part4_matrix);

    const afcipherString = xorHexStrings(matrixToString(mMatrices),cipherString);

    // Divide part1 into a 1x16 matrix and perform right shifts on substitutionMatrix
    const upSubMatrix = performRightShifts([...substitutionMatrix], hexStringToMatrix(part1));

    const icipherString=xorFunction2(part1, afcipherString);

    const revCC=rCascadingXORs(hashedMessage.substring(31,33), icipherString);

    // Convert cipherString into matrices
    const initialCipherMatrix = hexStringToMatrixBlocks(revCC);

    // Reverse substitution
    const RSubMatrix = reverseSubstitution(initialCipherMatrix, upSubMatrix);

    const intString=matrixToString(RSubMatrix);

    const rCstring=rCascadingXORs(part1,intString);

    const pivot=adjacentXORs(rCstring);

    const finalXOR=xorFunction(pivot, rCstring);

    const intMatrices=hexStringToMatrixBlocks(finalXOR);

    // Convert part2 to 4x4 matrix
    const part2_matrix = stringToMatrix(part2);

    // XOR re-substituted matrix and part2 for intermediate cipher
    const IntResults = xorMatrices(part2_matrix, convertTo4x4Blocks(intMatrices));

    const plainMatrices=reverseSubstitution(IntResults,substitutionMatrix);
    // Convert intermediate results back to plain text
    const plainText = hexMatrixToPlainText(plainMatrices);

    return plainText;
}

// Generate a more complex substitution matrix
// Function to generate substitution matrix
function generateSubstitutionMatrix(key) {
    // Initialize an array containing hexadecimal numbers from 00 to ff
    const hexArray = Array.from({ length: 256 }, (_, i) => i.toString(16).padStart(2, '0'));

    // Use the key to seed the random number generator
    const seededRandom = seedrandom(key);

    // Shuffle the array using Fisher-Yates shuffle algorithm
    for (let i = hexArray.length - 1; i > 0; i--) {
        const j = Math.floor(seededRandom() * (i + 1));
        [hexArray[i], hexArray[j]] = [hexArray[j], hexArray[i]];
    }

    // Reshape the shuffled array into a 16x16 matrix
    const matrix = [];
    for (let i = 0; i < 16; i++) {
        matrix.push(hexArray.slice(i * 16, (i + 1) * 16));
    }

    return matrix;
}


// Helper functions

function xorHexStrings(hex128, hexLong) {
    // Ensure the long hex string's length is a multiple of 128 bits (32 hex characters)
    if (hexLong.length % 32 !== 0) {
        console.log(hexLong.length);
        throw new Error('The length of the longer hex string must be a multiple of 128 bits.');
    }

    // Ensure the first hex string is exactly 128 bits (32 hex characters)
    if (hex128.length !== 32) {
        console.log(hex128.length);
        throw new Error('The first hex string must be exactly 128 bits.');
    }

    let result = '';

    for (let i = 0; i < hexLong.length; i++) {
        let hex128Index = i % 32;
        let xorValue = parseInt(hex128[hex128Index], 16) ^ parseInt(hexLong[i], 16);
        result += xorValue.toString(16);
    }

    return result;
}

function hexToInt(hex) {
    return parseInt(hex, 16);
}

function intToHex(int) {
    // Ensure the integer is within the valid byte range
    if (int < 0 || int > 255) return '00';
    return int.toString(16).padStart(2, '0'); // Convert to hex and ensure it's 2 characters long
}

function findIndexInFlatMatrix(flatMatrix, hexValue) {
    return flatMatrix.indexOf(hexValue);
}

function moduloMatrices(matrix1, matrix2) {
    // Flatten both matrices to easily access elements by index
    const flatMatrix1 = matrix1.flat();
    const flatMatrix2 = matrix2.flat();

    // Initialize a result matrix with the same dimensions
    const resultMatrix = Array.from({ length: 4 }, () => Array(4).fill('00'));

    // Perform the modulo operation as specified
    for (let i = 0; i < 16; i++) {
        const val1 = hexToInt(flatMatrix1[i]);
        const val2 = hexToInt(flatMatrix2[15 - i]);

        if (val2 === 0) {
            // Avoid modulo by zero
            resultMatrix[Math.floor(i / 4)][i % 4] = '00';
            continue;
        }

        let result = val1 % val2;
        let hexResult = intToHex(result);

        let indexInMatrix1 = findIndexInFlatMatrix(flatMatrix1, hexResult);
        let indexInMatrix2 = findIndexInFlatMatrix(flatMatrix2, hexResult);

        if (indexInMatrix1 !== -1 || indexInMatrix2 !== -1) {
            // Perform XOR if result is found in either matrix
            result = val1 ^ hexToInt(flatMatrix2[15 - i]);
            hexResult = intToHex(result);
            indexInMatrix1 = findIndexInFlatMatrix(flatMatrix1, hexResult);
            indexInMatrix2 = findIndexInFlatMatrix(flatMatrix2, hexResult);

            if (indexInMatrix1 !== -1 || indexInMatrix2 !== -1) {
                // Calculate absolute position difference and add to XOR result
                const posDiff = Math.abs((indexInMatrix1 !== -1 ? indexInMatrix1 : indexInMatrix2) - i);
                result = (result + posDiff) % 256; // Ensure result is within byte range
                hexResult = intToHex(result);
            }
        }

        resultMatrix[Math.floor(i / 4)][i % 4] = hexResult;
    }

    // console.log(resultMatrix);
    return resultMatrix;
}


function xorFunction2(pivot, hexString) {
    let result = "";

    // Ensure the pivot is 16 bytes (32 hex characters)
    if (pivot.length !== 32) {
        throw new Error("Pivot must be 32 hexadecimal characters (16 bytes) long");
    }

    // Convert pivot to an array of bytes
    let pivotBytes = [];
    for (let i = 0; i < pivot.length; i += 2) {
        pivotBytes.push(parseInt(pivot.substr(i, 2), 16));
    }

    // Iterate through the hexString 32 characters (16 bytes) at a time
    for (let i = 0; i < hexString.length; i += 32) {
        // Extract 32 characters (16 bytes) from the hexString
        let hexChunk = hexString.substr(i, 32);
        
        // Check if the chunk is less than 32 characters and pad it if necessary
        if (hexChunk.length < 32) {
            hexChunk = hexChunk.padEnd(32, '0');
        }

        // Convert hexChunk to an array of bytes
        let chunkBytes = [];
        for (let j = 0; j < hexChunk.length; j += 2) {
            chunkBytes.push(parseInt(hexChunk.substr(j, 2), 16));
        }

        // Perform XOR operation between pivotBytes and chunkBytes
        for (let k = 0; k < 16; k++) {
            let xorResult = pivotBytes[k] ^ chunkBytes[k];
            // Convert result back to hexadecimal and append to result string
            result += xorResult.toString(16).padStart(2, '0');
        }
    }

    return result;
}


function cascadingXOR2(key, cipherText) {
    let result = "";
    let initialXORValue = parseInt(key.slice(0, 2), 16);

    for (let i = 0; i < cipherText.length; i += 2) {
        let char1 = parseInt(cipherText.slice(i, i + 2), 16);
        initialXORValue = initialXORValue ^ char1;
        result += initialXORValue.toString(16).padStart(2, '0');  // Ensure the result is two hex digits
    }

    return result;
}

function xorFunction(pivot, hexString) {
    let result = "";

    // Convert pivot to a number
    let pivotByte = parseInt(pivot, 16);

    // Iterate through the hexString two characters at a time
    for (let i = 0; i < hexString.length; i += 2) {
        // Extract two characters (1 byte) from the hexString
        let byte = hexString.substr(i, 2);

        // Perform XOR operation between pivotByte and the byte
        let xorResult = pivotByte ^ parseInt(byte, 16);

        // Convert result back to hexadecimal and append to result string
        result += xorResult.toString(16).padStart(2, '0');
    }

    return result;
}

function rCascadingXORs(key, finalCipherText) {
    let originalCipherText = "";
    let firstTwoKeyChars = key.slice(0, 2);
    
    // Create a copy of finalCipherText with first two characters of the key appended at the start
    let appendedFinalCipherText = firstTwoKeyChars + finalCipherText;

    // Perform the reverse XOR operation
    for (let i = 0; i < finalCipherText.length; i += 2) {
        let char1 = parseInt(finalCipherText.slice(i, i + 2), 16);
        let char2 = parseInt(appendedFinalCipherText.slice(i, i + 2), 16);
        let originalChar = char1 ^ char2;
        originalCipherText += originalChar.toString(16).padStart(2, '0');  // Ensure the result is two hex digits
    }

    return originalCipherText;
}

function cascadingXOR(part1, intString, pivot) {
    let result = "";
    let keyByte = parseInt(part1.substr(0, 2), 16); // Extract the first byte (2 characters) of the key as a number

    for (let i = 0; i < intString.length; i += 2) {
        let intByte = parseInt(intString.substr(i, 2), 16); // Extract 1 byte (2 characters) from the input string
        let xorResult = keyByte ^ intByte ^ parseInt(pivot, 16); // Perform XOR operation
        result += xorResult.toString(16).padStart(2, '0'); // Convert result to hex and append to result string

        // Update keyByte for the next iteration
        keyByte = xorResult;
    }

    return result;
}

function adjacentXORs(hexString) {
    let result = 0;
    for (let i = 0; i < hexString.length; i += 2) {
        let byte = parseInt(hexString.substr(i, 2), 16); // Parse two characters (1 byte) as hexadecimal
        result ^= byte; // Perform XOR operation with the result
    }
    return result.toString(16).toUpperCase().padStart(2, '0'); // Convert result to hex and ensure it's two digits
}

function stringToMatrix(str) {
    if (str.length !== 32) {
        throw new Error('Input string must be 128 bits long.');
    }

    const matrix = [];
    let index = 0;

    for (let i = 0; i < 4; i++) {
        matrix[i] = [];
        for (let j = 0; j < 4; j++) {
            const byte = str.slice(index, index + 2); // Take two characters (1 byte)
            matrix[i][j] = byte;
            index += 2; // Move to the next byte
        }
    }

    return matrix;
}

function divideIntoMatrices(hexString) {
    const matrices = [];
    for (let i = 0; i < hexString.length; i += 32) {
        const matrix = [];
        for (let j = 0; j < 32; j += 2) {
            matrix.push(hexString.slice(i + j, i + j + 2));
        }
        matrices.push(matrix);
    }
    return matrices;
}

function performSubstitutionOnBlocks(matrices, substitutionMatrix) {
    // Iterate through each block
    for (let block of matrices) {
        // Iterate through each element in the block
        for (let i = 0; i < block.length; i++) {
            // Convert hexadecimal to decimal
            const decimalValue = parseInt(block[i], 16);
            // Extract row and column indices
            const rowIndex = Math.floor(decimalValue / 16); // First 4 bits
            const colIndex = decimalValue % 16; // Last 4 bits
            // Perform substitution using the substitution matrix
            block[i] = substitutionMatrix[rowIndex][colIndex];
        }
    }
    return matrices;
}

function xorMatrices(matrix1, matrix2) {
    if (matrix1.length !== 4 || matrix1[0].length !== 4) {
        throw new Error('First matrix must be a 4x4 matrix.');
    }

    const xorResults = [];
    for (let i = 0; i < matrix2.length; i++) {
        const block = matrix2[i];
        if (block.length !== 4 || block[0].length !== 4) {
            throw new Error('Each block of the second matrix must be a 4x4 matrix.');
        }

        const xorBlock = [];
        for (let row = 0; row < 4; row++) {
            const xorRow = [];
            for (let col = 0; col < 4; col++) {
                const value1 = parseInt(matrix1[row][col], 16);
                const value2 = parseInt(block[row][col], 16);
                const xorValue = value1 ^ value2;
                xorRow.push(xorValue.toString(16).padStart(2, '0'));
            }
            xorBlock.push(xorRow);
        }
        xorResults.push(xorBlock);
    }

    // Convert xorResults to mx16 matrices
    const finalResult = [];
    let currentRow = [];

    xorResults.forEach(block => {
        block.forEach(row => {
            currentRow.push(...row);
            if (currentRow.length === 16) {
                finalResult.push(currentRow);
                currentRow = [];
            }
        });
    });

    // If there's any remaining row, pad it to make it 16 columns wide
    if (currentRow.length > 0) {
        while (currentRow.length < 16) {
            currentRow.push('00');
        }
        finalResult.push(currentRow);
    }

    return finalResult;
}

function hexStringToMatrixBlocks(hexString) {
    const bytesPerRow = 16; // Each row contains 16 bytes
    const blockSize = bytesPerRow * 2; // Each block contains 16 characters representing 16 bytes
    const blocks = [];
    const numRows = Math.ceil(hexString.length / blockSize); // Calculate number of rows

    for (let i = 0; i < numRows; i++) {
        const block = [];
        const startIndex = i * blockSize;
        for (let j = 0; j < bytesPerRow; j++) {
            const byteHex = hexString.substring(startIndex + j * 2, startIndex + (j + 1) * 2);
            block.push(byteHex.padStart(2, '0'));
        }
        blocks.push(block);
    }

    return blocks;
}

function hexStringToMatrix(hexString) {
    if (hexString.length !== 32) {
        throw new Error("Hexadecimal string must be 32 characters long (128 bits).");
    }

    const matrix = [];

    for (let i = 0; i < 16; i++) {
        const byteHex = hexString.substr(i * 2, 2);
        matrix.push(byteHex);
    }

    return matrix;
}

function performRightShifts(subMatrix, part2Matrix) {
    const numRows = subMatrix.length;
    for (let i = 0; i < numRows; i++) {
        const shiftCount = parseInt(part2Matrix[i], 16);
        subMatrix[i] = rightShiftRow(subMatrix[i], shiftCount);
    }
    return subMatrix;
}

function rightShiftRow(row, shiftCount) {
    const shiftedRow = new Array(row.length);
    for (let i = 0; i < row.length; i++) {
        shiftedRow[(i + shiftCount) % row.length] = row[i];
    }
    return shiftedRow;
}

function reverseSubstitution(cipherMatrix, substitutionMatrix) {
    const newMatrix = [];

    for (let row = 0; row < cipherMatrix.length; row++) {
        const newRow = [];
        for (let col = 0; col < cipherMatrix[0].length; col++) {
            const cipherElement = cipherMatrix[row][col];
            let substitutionRow, substitutionCol;
            for (let i = 0; i < substitutionMatrix.length; i++) {
                for (let j = 0; j < substitutionMatrix.length; j++) {
                    if (cipherElement === substitutionMatrix[i][j]) {
                        substitutionRow = i.toString(16);
                        substitutionCol = j.toString(16);
                        break;
                    }
                }
            }
            newRow.push(substitutionRow + substitutionCol);
        }
        newMatrix.push(newRow);
    }
    return newMatrix;
}

function convertTo4x4Blocks(matrix) {
    const newMatrix = matrix.map(block => {
        if (block.length !== 16) {
            throw new Error('Each block must be a 1x16 array.');
        }
        const newBlock = [];
        for (let i = 0; i < 16; i += 4) {
            newBlock.push(block.slice(i, i + 4));
        }
        return newBlock;
    });

    return newMatrix;
}

// Divide input key into four parts
function divideString(str) {
    if (str.length !== 128) {
        throw new Error("Input string must be 256 characters long.");
    }
    const partLength = str.length / 4;
    return [
        str.slice(0, partLength),
        str.slice(partLength, 2 * partLength),
        str.slice(2 * partLength, 3 * partLength),
        str.slice(3 * partLength)
    ];
}

// Function to remove PKCS#7 padding from the plain text
function removePadding(utf8String) {
    const paddingChar = utf8String.charCodeAt(utf8String.length - 1);
    const paddingLength = utf8String.split('').filter(char => char.charCodeAt(0) === paddingChar).length;
    return utf8String.slice(0, -paddingLength);
}

function hexMatrixToPlainText(matrix) {
    let hexString = '';
    for (let block of matrix) {
        for (let row of block) {
            for (let byte of row) {
                hexString += byte;
            }
        }
    }

    // Convert hex string to Uint8Array
    let byteArray = new Uint8Array(hexString.match(/.{1,2}/g).map(byte => parseInt(byte, 16)));
    
    // Decode Uint8Array to UTF-8 string
    let utf8String = new TextDecoder('utf-8').decode(byteArray);

    // Remove PKCS#7 padding from the plain text
    return removePadding(utf8String);
}

function textToHex(text) {
    // Encode text as UTF-8
    const utf8Bytes = new TextEncoder().encode(text);

    // Pad the UTF-8 bytes using PKCS#7
    const paddedBytes = pkcs7Pad(utf8Bytes);

    // Convert padded bytes to hexadecimal representation
    const hexString = Array.from(paddedBytes).map(byte => byte.toString(16).padStart(2, '0')).join('');

    return hexString;
}

// Function to pad using PKCS#7
function pkcs7Pad(data) {
    const blockSize = 16;
    const paddingSize = blockSize - (data.length % blockSize);
    const padding = new Uint8Array(paddingSize).fill(paddingSize);
    const paddedArray = new Uint8Array(data.length + paddingSize);
    paddedArray.set(data);
    paddedArray.set(padding, data.length);
    return paddedArray;
}

function matrixToString(matrix) {
    let str = '';
    for (let i = 0; i < matrix.length; i++) {
        for (let j = 0; j < matrix[i].length; j++) {
            str += matrix[i][j];
        }
    }
    return str;
}

module.exports = {
    encrypt,
    decrypt,
    generateSubstitutionMatrix
};