// Import modules
require('dotenv').config();
const axios = require('axios');
const fs = require('fs');
const https = require('https');
const readline = require('readline');
const { performance } = require('perf_hooks');

// Konfigurasi sertifikat dan private key untuk HTTPS
const agent = new https.Agent({
    cert: fs.readFileSync(process.env.CERT_PATH),
    key: fs.readFileSync(process.env.KEY_PATH),
    rejectUnauthorized: false
});


// ---------------------------------------------------------------


// Fungsi untuk membuat payload acak sesuai ukuran KB
function generatePayload(sizeKB) {
    const sizeBytes = sizeKB * 1024;
    const characters = 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789';
    return Array.from({ length: sizeBytes }, () =>
        characters.charAt(Math.floor(Math.random() * characters.length))
    ).join('');
}

// Fungsi untuk membuat format karakter sesuai panjang payload
function generateFormatChar(payload) {
    const formatChars = '$%&#@!*';
    return Array.from({ length: payload.length }, () =>
        formatChars.charAt(Math.floor(Math.random() * formatChars.length))
    ).join('');
}

// Fungsi untuk menghasilkan Certificate Signing Request (CSR)
function generateCSR() {
    const csr = fs.readFileSync(process.env.KEY_PATH_CSR, 'utf-8');
    if (!csr) {
        throw new Error("CSR generation failed. Ensure the CSR file exists and is accessible.");
    }
    return csr;
}

// Fungsi untuk memilih keyId berdasarkan algoritma dan panjang kunci untuk seal
function getKeyIdSeal(algorithm, keyLength) {
    const keyIds = {
        AES_256: process.env.KEY_ID_SEAL_AES_256,
        RSA_2048: process.env.KEY_ID_SEAL_RSA_2048,
        RSA_3072: process.env.KEY_ID_SEAL_RSA_3072,
        RSA_4096: process.env.KEY_ID_SEAL_RSA_4096,
    };

    if (algorithm === "AES" && keyLength === 256) {
        return keyIds.AES_256;
    } else if (algorithm === "RSA") {
        if (keyLength === 2048) return keyIds.RSA_2048;
        if (keyLength === 3072) return keyIds.RSA_3072;
        if (keyLength === 4096) return keyIds.RSA_4096;
    }
    return null;
}

// Fungsi untuk memilih keyId berdasarkan algoritma dan panjang kunci untuk encrypt
function getKeyIdEncrypt(algorithm, keyLength) {
    const keyIds = {
        AES_256: process.env.KEY_ID_ENCRYPT_AES_256,
        RSA_2048: process.env.KEY_ID_ENCRYPT_RSA_2048,
        RSA_3072: process.env.KEY_ID_ENCRYPT_RSA_3072,
        RSA_4096: process.env.KEY_ID_ENCRYPT_RSA_4096,
    };
    
    if (algorithm === "AES" && keyLength === 256) {
        return keyIds.AES_256;
    } else if (algorithm === "RSA") {
        if (keyLength === 2048) return keyIds.RSA_2048;
        if (keyLength === 3072) return keyIds.RSA_3072;
        if (keyLength === 4096) return keyIds.RSA_4096;
    }
    return null;
}

// Fungsi untuk memilih keyId berdasarkan algoritma dan panjang kunci untuk sign
function getKeyIdSign(algorithm, keyLength) {
    const keyIds = {
        ECDSA: process.env.KEY_ID_SIGN_ECDSA,
        RSA_2048: process.env.KEY_ID_SIGN_RSA_2048,
        RSA_3072: process.env.KEY_ID_SIGN_RSA_3072,
        RSA_4096: process.env.KEY_ID_SIGN_RSA_4096,
    };
    
    if (algorithm === "ECDSA") {
        return keyIds.ECDSA;
    } else if (algorithm === "RSA") {
        if (keyLength === 2048) return keyIds.RSA_2048;
        if (keyLength === 3072) return keyIds.RSA_3072;
        if (keyLength === 4096) return keyIds.RSA_4096;
    }
    return null;
}

// Fungsi untuk mendapatkan keyId berdasarkan algoritma dan panjang kunci untuk sertifikat
function getKeyIdCertSign(algorithm, keyLength) {
    const keyIds = {
        ECDSA: process.env.KEY_ID_CERTSIGN_ECDSA,
        RSA_3072: process.env.KEY_ID_CERTSIGN_RSA_3072,
        RSA_4096: process.env.KEY_ID_CERTSIGN_RSA_4096
    };

    if (algorithm === "ECDSA") {
        return keyIds.ECDSA;
    } else if (algorithm === "RSA") {
        if (keyLength === 3072) return keyIds.RSA_3072;
        if (keyLength === 4096) return keyIds.RSA_4096;
    }
    return null;
}

// Fungsi untuk mendapatkan wrappingKeyId berdasarkan algoritma dan panjang kunci
function getWrappingKeyId(algorithm, keyLength) {
    const keyIds = {
        AES_256: process.env.WRAPPING_KEY_ID_AES_256,
        RSA_3072: process.env.WRAPPING_KEY_ID_RSA_3072,
        RSA_4096: process.env.WRAPPING_KEY_ID_RSA_4096
    };

    if (algorithm === "AES" && keyLength === 256) {
        return keyIds.AES_256;
    } else if (algorithm === "RSA") {
        if (keyLength === 3072) return keyIds.RSA_3072;
        if (keyLength === 4096) return keyIds.RSA_4096;
    }
    return null;
}

// ---------------------------------------------------------------


// Fungsi untuk login dan mendapatkan session token
async function login() {
    try {
        const response = await axios.post(`${process.env.URL_SGKMS}/v1.0/agent/login`, { 
            slotId: parseInt(process.env.SLOT_ID),
            password: process.env.PASSWORD_SGKMS 
        }, {
            headers: { 'Content-Type': 'application/json' },
            httpsAgent: agent
        });

        // Mengecek apakah sessionToken ada dalam response
        if (response.data && response.data.result && response.data.result.sessionToken) {
            // console.log("Login successful. Session Token:", response.data.result.sessionToken);
            return response.data.result.sessionToken;
        } else {
            console.error("Session token not found in the response.");
            return null;
        }
    } catch (error) {
        console.error("Login failed:", error.response ? error.response.data : error.message);
        throw error;
    }
}

// Fungsi untuk menghasilkan random number berdasarkan panjang yang diminta
async function generateRandomNumber(length) {
    try {
        const sessionToken = await login();
        
        // Validasi input panjang
        if (!Number.isInteger(length) || length <= 0) {
            throw new Error("Length must be a positive integer.");
        }

        const requestBody = {
            sessionToken: sessionToken,
            slotId: parseInt(process.env.SLOT_ID),
            length: length
        };

        // console.log("Attempting RNG with the following parameters:");
        // console.log("Request Body:", JSON.stringify(requestBody, null, 2));

        // Mengirim permintaan ke endpoint RNG
        const response = await axios.post(`${process.env.URL_SGKMS}/v1.0/rng`, requestBody, {
            headers: { 'Content-Type': 'application/json' },
            httpsAgent: agent
        });

        // console.log("RNG Response:", JSON.stringify(response.data, null, 2));
        return response.data;
    } catch (error) {
        console.error("Random number generation failed:", error.response ? error.response.data : error.message);
        throw error;
    }
}

// Fungsi untuk generate MAC (Message Authentication Code)
async function generateMAC(payloadSizeKB, hashAlgo) {
    try {
        const sessionToken = await login();
        const data = generatePayload(payloadSizeKB);
        const maxDataSize = 700; 

        // Validasi ukuran data
        if (payloadSizeKB > maxDataSize) {
            throw new Error("Data size exceeds the maximum limit of 700 KB");
        }

        // Validasi nilai hashAlgo
        const validHashAlgos = ["CMAC", "GMAC-256", "HMAC-SHA256"];
        if (!validHashAlgos.includes(hashAlgo)) {
            throw new Error(`Invalid hash algorithm. Please choose one of: ${validHashAlgos.join(", ")}`);
        }

        const requestBody = {
            sessionToken: sessionToken,
            slotId: parseInt(process.env.SLOT_ID),
            keyId: process.env.KEY_ID_MAC,
            hashAlgo: hashAlgo,
            data: data
        };

        // console.log("Attempting MAC Generation with the following parameters:");
        // console.log("Request Body:", JSON.stringify(requestBody, null, 2));

        const response = await axios.post(`${process.env.URL_SGKMS}/v1.0/mac/generate`, requestBody, {
            headers: { 'Content-Type': 'application/json' },
            httpsAgent: agent
        });

        // console.log("MAC Generation Response:", JSON.stringify(response.data, null, 2));
        return response.data;
    } catch (error) {
        console.error("MAC Generation failed:", error.response ? error.response.data : error.message);
        throw error;
    }
}

// Fungsi untuk melakukan seal (enkripsi) data dengan metadata
async function sealData(payloadSizeKB, algorithm, keyLength) {
    try {
        const sessionToken = await login();
        const payload = generatePayload(payloadSizeKB); 
        const keyId = getKeyIdSeal(algorithm, keyLength);

        if (!keyId) {
            throw new Error(`Key ID tidak ditemukan untuk algoritma ${algorithm} dengan panjang kunci ${keyLength}`);
        }

        const requestBody = {
            sessionToken: sessionToken,
            slotId: parseInt(process.env.SLOT_ID),
            keyId: keyId,
            plaintext: [payload]
        };

        // console.log("Attempting Seal with the following parameters:");
        // console.log("Request Body:", JSON.stringify(requestBody, null, 2));

        const response = await axios.post(`${process.env.URL_SGKMS}/v1.0/seal`, requestBody, {
            headers: { 'Content-Type': 'application/json' },
            httpsAgent: agent
        });

        // console.log("Seal Response:", JSON.stringify(response.data, null, 2));
        return response.data;
    } catch (error) {
        console.error("Seal operation failed:", error.response ? error.response.data : error.message);
        throw error;
    }
}

// Fungsi untuk enkripsi data
async function encryptData(payloadSizeKB, algorithm, keyLength, useSessionKey) {
    try {
        const sessionToken = await login();
        const payload = generatePayload(payloadSizeKB);
        const keyId = getKeyIdEncrypt(algorithm, keyLength);

        if (!keyId) {
            throw new Error(`Key ID tidak ditemukan untuk algoritma ${algorithm} dengan panjang kunci ${keyLength}`);
        }

        // Konfigurasi objek plaintext sesuai algoritma
        let plaintext;
        if (algorithm === "AES" && keyLength === 256) {
            // Menambahkan AAD jika AES dipilih
            plaintext = [{ text: payload, aad: "Additional Authentication Data" }];
        } else if (algorithm === "RSA" && [2048, 3072, 4096].includes(keyLength)) {
            // RSA tidak membutuhkan AAD
            plaintext = [{ text: payload }];
        } else {
            throw new Error("Algoritma atau panjang kunci yang tidak valid.");
        }

        const requestBody = {
            sessionToken: sessionToken,
            slotId: parseInt(process.env.SLOT_ID),
            keyId: keyId,
            useSessionKey: algorithm === "AES" ? undefined : useSessionKey,
            plaintext: plaintext
        };

        // console.log("Attempting Encryption with the following parameters:");
        // console.log("Request Body:", JSON.stringify(requestBody, null, 2));

        const response = await axios.post(`${process.env.URL_SGKMS}/v1.0/encrypt`, requestBody, {
            headers: { 'Content-Type': 'application/json' },
            httpsAgent: agent
        });

        // console.log("Encrypt Response:", JSON.stringify(response.data, null, 2));
        return response.data;
    } catch (error) {
        console.error("Encryption failed:", error.response ? error.response.data : error.message);
        throw error;
    }
}

// Fungsi untuk melakukan tokenisasi data dengan format yang disesuaikan
async function tokenizeData(payloadSizeKB) {
    try {
        const sessionToken = await login();
        const textPayload = generatePayload(payloadSizeKB);
        const formatChar = generateFormatChar(textPayload);

        // Validasi panjang textPayload dan formatChar
        if (textPayload.length !== formatChar.length) {
            throw new Error("Text and formatChar must have the same length.");
        }

        const requestBody = {
            sessionToken: sessionToken,
            slotId: parseInt(process.env.SLOT_ID),
            keyId: process.env.KEY_ID_TOKENIZE,
            plaintext: [{
                text: textPayload,
                formatChar: formatChar
            }]
        };

        // console.log("Attempting Tokenization with the following parameters:");
        // console.log("Request Body:", JSON.stringify(requestBody, null, 2));

        const response = await axios.post(`${process.env.URL_SGKMS}/v1.0/tokenize`, requestBody, {
            headers: { 'Content-Type': 'application/json' },
            httpsAgent: agent
        });

        // console.log("Tokenization Response:", JSON.stringify(response.data, null, 2));
        return response.data;
    } catch (error) {
        console.error("Tokenization failed:", error.response ? error.response.data : error.message);
        throw error;
    }
}

// Fungsi untuk melakukan tanda tangan (signing) data
async function signData(payloadSizeKB, algorithm, keyLength) {
    try {
        const sessionToken = await login();
        const payload = generatePayload(payloadSizeKB); 
        const keyId = getKeyIdSign(algorithm, keyLength); 

        if (!keyId) {
            throw new Error(`Key ID tidak ditemukan untuk algoritma ${algorithm} dengan panjang kunci ${keyLength}`);
        }

        const requestBody = {
            sessionToken: sessionToken,
            slotId: parseInt(process.env.SLOT_ID),
            keyId: keyId,
            data: payload
        };

        // console.log("Attempting Sign with the following parameters:");
        // console.log("Request Body:", JSON.stringify(requestBody, null, 2));

        const response = await axios.post(`${process.env.URL_SGKMS}/v1.0/sign`, requestBody, {
            headers: { 'Content-Type': 'application/json' },
            httpsAgent: agent
        });
        
        // console.log("Sign Response:", JSON.stringify(response.data, null, 2));
        return response.data;
    } catch (error) {
        console.error("Sign operation failed:", error.response ? error.response.data : error.message);
        throw error;
    }
}

// Fungsi untuk menandatangani Certificate Signing Request (CSR)
async function signCertificate(algorithm, keyLength) {
    try {
        const sessionToken = await login();
        const slotId = parseInt(process.env.SLOT_ID); 
        const validityPeriod = 90; 
        const keyId = getKeyIdCertSign(algorithm, keyLength); 

        if (!keyId) {
            throw new Error(`Key ID tidak ditemukan untuk algoritma ${algorithm} dengan panjang kunci ${keyLength}`);
        }

        const csr = generateCSR();

        const requestBody = {
            sessionToken: sessionToken,
            slotId: slotId,
            validityPeriod: validityPeriod,
            keyId: keyId,
            csr: csr
        };

        // console.log("Attempting Certificate Signing with the following parameters:");
        // console.log("Request Body:", JSON.stringify(requestBody, null, 2));
        
        // Mengirim permintaan ke endpoint Certificate Signatures
        const response = await axios.post(`${process.env.URL_SGKMS}/v1.0/cert/sign`, requestBody, {
            headers: { 'Content-Type': 'application/json' },
            httpsAgent: agent
        });

        // console.log("Certificate Signing Response:", JSON.stringify(response.data, null, 2));
        return response.data;
    } catch (error) {
        console.error("Certificate signing failed:", error.response ? error.response.data : error.message);
        throw error;
    }
}

// Fungsi untuk mendapatkan informasi detail tentang kunci
async function getKeyInfo(keyId, keyVersion) {
    try {
        const sessionToken = await login();
        const slotId = parseInt(process.env.SLOT_ID);

        const requestBody = {
            sessionToken: sessionToken,
            slotId: slotId,
            keyId: keyId,
            keyVersion: keyVersion !== undefined ? keyVersion : undefined
        };
        
        // console.log("Attempting Key Information Retrieval with the following parameters:");
        // console.log("Request Body:", JSON.stringify(requestBody, null, 2));

        // Mengirim permintaan ke endpoint Key Information
        const response = await axios.post(`${process.env.URL_SGKMS}/v1.0/key/info`, requestBody, {
            headers: { 'Content-Type': 'application/json' },
            httpsAgent: agent
        });

        // console.log("Key Information Response:", JSON.stringify(response.data, null, 2));
        return response.data;
    } catch (error) {
        console.error("Key information retrieval failed:", error.response ? error.response.data : error.message);
        throw error;
    }
}

// Fungsi untuk mengambil secret dari SG-KMS
async function getSecret() {
    try {
        const sessionToken = await login();
        
        const requestBody = {
            sessionToken: sessionToken,
            slotId: parseInt(process.env.SLOT_ID),
            secretId: process.env.SECRET_ID
        };
        
        // console.log("Attempting Secret Retrieval with the following parameters:");
        // console.log("Request Body:", JSON.stringify(requestBody, null, 2));

        const response = await axios.post(`${process.env.URL_SGKMS}/v1.0/secret/get`, requestBody, {
            headers: { 'Content-Type': 'application/json' },
            httpsAgent: agent
        });

        // console.log("Get Secret Response:", JSON.stringify(response.data, null, 2));
        return response.data;
    } catch (error) {
        console.error("Secret retrieval failed:", error.response ? error.response.data : error.message);
        throw error;
    }
}

// Fungsi untuk menghasilkan pasangan kunci eksternal
async function externalGenerateKeyPair(algo, algoLength, withCert = false, wrappingAlgorithm, wrappingKeyLength) {
    try {
        const sessionToken = await login();
        const slotId = parseInt(process.env.SLOT_ID);
        const wrappingKeyId = getWrappingKeyId(wrappingAlgorithm, wrappingKeyLength);

        if (!wrappingKeyId) {
            throw new Error(`Wrapping Key ID not found for wrapping algorithm ${wrappingAlgorithm} and key length ${wrappingKeyLength}`);
        }

        // Validasi algoritma dan panjang kunci untuk pasangan kunci
        if (algo === "RSA" && ![2048, 3072, 4096].includes(algoLength)) {
            throw new Error("Invalid RSA key length. Supported lengths: 2048, 3072, 4096.");
        }
        if (algo === "ECDSA P-256" && algoLength !== undefined) {
            throw new Error("ECDSA P-256 does not require key length.");
        }

        const requestBody = {
            sessionToken: sessionToken,
            slotId: slotId,
            algo: algo,
            wrappingKeyId: wrappingKeyId
        };

        if (algo === "RSA") {
            requestBody.algoLength = algoLength;
        }
        if (withCert) {
            requestBody.withCert = true;
        }

        // console.log("Attempting Key Pair Generation with the following parameters:");
        // console.log("Request Body:", JSON.stringify(requestBody, null, 2));

        // Mengirim permintaan ke endpoint Generate Key Pair
        const response = await axios.post(`${process.env.URL_SGKMS}/v1.0/external/keypair/generate`, requestBody, {
            headers: { 'Content-Type': 'application/json' },
            httpsAgent: agent
        });

        // console.log("Key Pair Generation Response:", JSON.stringify(response.data, null, 2));
        
        // Validasi respons API
        if (response.data && response.data.result) {
            const { publicKeyOrCert, wrappedPrivateKey } = response.data.result;
            if (!publicKeyOrCert) throw new Error("Public key not found in response.");
            if (!wrappedPrivateKey) throw new Error("Private key not found in response.");
            return { publicKey: publicKeyOrCert, privateKey: wrappedPrivateKey };
        } else {
            throw new Error("Unexpected response structure from Key Pair Generation API.");
        }
    } catch (error) {
        console.error("Key pair generation failed:", error.response ? error.response.data : error.message);
        throw error;
    }
}

// Fungsi untuk menghasilkan kunci AES-256-GCM eksternal
async function externalGenerateAESKey() {
    try {
        const sessionToken = await login();
        const slotId = parseInt(process.env.SLOT_ID);
        const wrappingKeyId = process.env.WRAPPING_KEY_ID_AES_256;

        if (!wrappingKeyId) {
            throw new Error("Wrapping Key ID for AES is not defined in the environment variables.");
        }

        const requestBody = {
            sessionToken: sessionToken,
            slotId: slotId,
            algo: "AES",
            algoLength: 256,
            wrappingKeyId: wrappingKeyId
        };

        // console.log("Attempting AES Key Generation with the following parameters:");
        // console.log("Request Body:", JSON.stringify(requestBody, null, 2));

        // Mengirim permintaan ke endpoint Generate AES Key
        const response = await axios.post(`${process.env.URL_SGKMS}/v1.0/external/key/generate`, requestBody, {
            headers: { 'Content-Type': 'application/json' },
            httpsAgent: agent
        });

        // console.log("AES Key Generation Response:", JSON.stringify(response.data, null, 2));
        
        if (response.data && response.data.result && response.data.result.wrappedKey) {
            return { wrappedKey: response.data.result.wrappedKey };
        } else {
            throw new Error("Wrapped Key not found in AES Key Generation response.");
        }
    } catch (error) {
        console.error("AES key generation failed:", error.response ? error.response.data : error.message);
        throw error;
    }
}

// Fungsi untuk menghasilkan MAC dengan kunci AES eksternal
async function externalGenerateMAC(payloadSizeKB, hashAlgo) {
    try {
        const sessionToken = await login();
        const data = generatePayload(payloadSizeKB);
        const maxDataSize = 700; 

        // Validasi ukuran data
        if (payloadSizeKB > maxDataSize) {
            throw new Error("Data size exceeds the maximum limit of 700 KB");
        }

        // Validasi nilai hashAlgo
        const validHashAlgos = ["CMAC", "HMAC-SHA256", "GMAC-256"];
        if (!validHashAlgos.includes(hashAlgo)) {
            throw new Error(`Invalid hash algorithm. Please choose one of: ${validHashAlgos.join(", ")}`);
        }

        // Mendapatkan wrappedKey
        const { wrappedKey } = await externalGenerateAESKey();
        if (!wrappedKey) {
            throw new Error("Wrapped Key is undefined. Unable to proceed with MAC generation.");
        }

        const slotId = parseInt(process.env.SLOT_ID);
        const wrappingKeyId = process.env.WRAPPING_KEY_ID_AES_256;

        const requestBody = {
            sessionToken: sessionToken,
            slotId: slotId,
            wrappingKeyId: wrappingKeyId,
            wrappedKey: wrappedKey,
            hashAlgo: hashAlgo,
            data: data
        };

        // console.log("Attempting MAC Generation with the following parameters:");
        // console.log("Request Body:", JSON.stringify(requestBody, null, 2));
        
        // Mengirim permintaan ke endpoint Generate MAC
        const response = await axios.post(`${process.env.URL_SGKMS}/v1.0/external/mac/generate`, requestBody, {
            headers: { 'Content-Type': 'application/json' },
            httpsAgent: agent
        });

        // console.log("MAC Generation Response:", JSON.stringify(response.data, null, 2));
        return response.data;
    } catch (error) {
        console.error("MAC generation failed:", error.response ? error.response.data : error.message);
        throw error;
    }
}

// Fungsi untuk Seal data dengan kunci eksternal
async function externalSealData(payloadSizeKB, algorithm, keyLength, withCert = false, wrappingAlgorithm, wrappingKeyLength) {
    try {
        const sessionToken = await login();
        const payload = generatePayload(payloadSizeKB);

        let requestBody;
        if (algorithm === "AES") {
            const { wrappedKey } = await externalGenerateAESKey();
            const wrappingKeyId = process.env.WRAPPING_KEY_ID_AES_256;

            requestBody = {
                sessionToken: sessionToken,
                slotId: parseInt(process.env.SLOT_ID),
                wrappingKeyId: wrappingKeyId,
                wrappedKey: wrappedKey,
                plaintext: [payload]
            };
        } else if (algorithm === "RSA") {
            const { publicKey } = await externalGenerateKeyPair("RSA", keyLength, withCert, wrappingAlgorithm, wrappingKeyLength);

            requestBody = {
                sessionToken: sessionToken,
                slotId: parseInt(process.env.SLOT_ID),
                publicKeyOrCert: publicKey,
                plaintext: [payload]
            };
        } else {
            throw new Error("Unsupported algorithm.");
        }

        // console.log("Attempting Seal with the following parameters:");
        // console.log("Request Body:", JSON.stringify(requestBody, null, 2));

        // Mengirim permintaan ke endpoint Seal
        const response = await axios.post(`${process.env.URL_SGKMS}/v1.0/external/seal`, requestBody, {
            headers: { 'Content-Type': 'application/json' },
            httpsAgent: agent
        });

        // console.log("Seal Response:", JSON.stringify(response.data, null, 2));
        return response.data;
    } catch (error) {
        console.error("Seal operation failed:", error.response ? error.response.data : error.message);
        throw error;
    }
}

// Fungsi untuk enkripsi data dengan kunci eksternal
async function externalEncryptData(payloadSizeKB, algo, algoLength, withCert = false, wrappingAlgorithm, wrappingKeyLength, useSessionKey = false) {
    try {
        const sessionToken = await login();
        const payload = generatePayload(payloadSizeKB);

        let requestBody;
        if (algo === "AES") {
            const { wrappedKey } = await externalGenerateAESKey();
            const wrappingKeyId = process.env.WRAPPING_KEY_ID_AES_256;

            requestBody = {
                sessionToken: sessionToken,
                slotId: parseInt(process.env.SLOT_ID),
                wrappingKeyId: wrappingKeyId,
                wrappedKey: wrappedKey,
                plaintext: [{ text: payload, aad: "Additional Authentication Data" }]
            };
        } else if (algo === "RSA") {
            const { publicKey } = await externalGenerateKeyPair(algo, algoLength, withCert, wrappingAlgorithm, wrappingKeyLength);

            requestBody = {
                sessionToken: sessionToken,
                slotId: parseInt(process.env.SLOT_ID),
                publicKeyOrCert: publicKey,
                useSessionKey: useSessionKey,
                plaintext: [{ text: payload }]
            };
        } else {
            throw new Error("Unsupported algorithm.");
        }

        // console.log("Attempting Encryption with the following parameters:");
        // console.log("Request Body:", JSON.stringify(requestBody, null, 2));

        // Mengirim permintaan ke endpoint Encrypt
        const response = await axios.post(`${process.env.URL_SGKMS}/v1.0/external/encrypt`, requestBody, {
            headers: { 'Content-Type': 'application/json' },
            httpsAgent: agent
        });

        // console.log("Encrypt Response:", JSON.stringify(response.data, null, 2));
        return response.data;
    } catch (error) {
        console.error("Encrypt operation failed:", error.response ? error.response.data : error.message);
        throw error;
    }
}

// Fungsi untuk melakukan tokenisasi dengan kunci AES eksternal
async function externalTokenizeData(payloadSizeKB) {
    try {
        const sessionToken = await login();
        const textPayload = generatePayload(payloadSizeKB);
        const formatChar = generateFormatChar(textPayload);

        // Validasi panjang textPayload dan formatChar
        if (textPayload.length !== formatChar.length) {
            throw new Error("Text and formatChar must have the same length.");
        }

        const slotId = parseInt(process.env.SLOT_ID);
        const wrappingKeyId = process.env.WRAPPING_KEY_ID_AES_256;
        const { wrappedKey } = await externalGenerateAESKey();

        const requestBody = {
            sessionToken: sessionToken,
            slotId: slotId,
            wrappingKeyId: wrappingKeyId,
            wrappedKey: wrappedKey,
            plaintext: [{
                text: textPayload,
                formatChar: formatChar
            }]
        };

        // console.log("Attempting Tokenization with the following parameters:");
        // console.log("Request Body:", JSON.stringify(requestBody, null, 2));

        // Mengirim permintaan ke endpoint Tokenization
        const response = await axios.post(`${process.env.URL_SGKMS}/v1.0/external/tokenize`, requestBody, {
            headers: { 'Content-Type': 'application/json' },
            httpsAgent: agent
        });

        // console.log("Tokenization Response:", JSON.stringify(response.data, null, 2));
        return response.data;
    } catch (error) {
        console.error("Tokenization failed:", error.response ? error.response.data : error.message);
        throw error;
    }
}

// Fungsi untuk melakukan tanda tangan (signing) data dengan kunci eksternal
async function externalSignData(payloadSizeKB, algorithm, keyLength, wrappingAlgorithm, wrappingKeyLength, withCert = false) {
    try {
        const sessionToken = await login();
        const payload = generatePayload(payloadSizeKB);
        const { privateKey } = await externalGenerateKeyPair(algorithm, keyLength, withCert, wrappingAlgorithm, wrappingKeyLength); 

        const requestBody = {
            sessionToken: sessionToken,
            slotId: parseInt(process.env.SLOT_ID),
            wrappingKeyId: getWrappingKeyId(wrappingAlgorithm, wrappingKeyLength),
            wrappedKey: privateKey,
            data: payload
        };

        // console.log("Attempting Sign with the following parameters:");
        // console.log("Request Body:", JSON.stringify(requestBody, null, 2));

        // Mengirim permintaan ke endpoint Sign
        const response = await axios.post(`${process.env.URL_SGKMS}/v1.0/external/sign`, requestBody, {
            headers: { 'Content-Type': 'application/json' },
            httpsAgent: agent
        });

        // console.log("Sign Response:", JSON.stringify(response.data, null, 2));
        return response.data;
    } catch (error) {
        console.error("Sign operation failed:", error.response ? error.response.data : error.message);
        throw error;
    }
}

// ---------------------------------------------------------------


// Menu untuk memilih fungsi API
async function selectAPIFunction() {
    return new Promise((resolve) => {
        const rl = readline.createInterface({
            input: process.stdin,
            output: process.stdout
        });

        console.log("Select API Function for Stress Test:");
        console.log("1. Generate Random Number");
        console.log("2. Generate MAC");
        console.log("3. Seal Data");
        console.log("4. Data Encryption");
        console.log("5. Tokenization");
        console.log("6. Digital Signatures");
        console.log("7. Certificate Signatures");
        console.log("8. Key Information");
        console.log("9. Get Secret");
        console.log("10. Generate Key Pair");
        console.log("11. Generate AES Key");
        console.log("12. Generate MAC with Externally Stored AES Key");
        console.log("13. Seal with External Key");
        console.log("14. Encrypt with External Key");
        console.log("15. Tokenization with Externally Stored AES Key");
        console.log("16. Sign with External Key");

        rl.question("Enter the number of the function to test: ", async (answer) => {
            let apiFunction;
            let apiFunctionName;

            if (answer === '1') {
                apiFunctionName = "GenerateRandomNumber";
                let length;

                // Meminta panjang output untuk RNG
                await new Promise((rngResolve) => {
                    rl.question("Enter the desired length of the random number: ", (lengthInput) => {
                        length = parseInt(lengthInput);
                        if (!Number.isInteger(length) || length <= 0) {
                            console.log("Invalid length. Length must be a positive integer.");
                            process.exit(1);
                        }
                        rngResolve();
                    });
                });
                apiFunction = () => generateRandomNumber(length);

            } else if (answer === '2') {
                apiFunctionName = "GenerateMAC";
                let hashAlgo;
                // Meminta pilihan hashAlgo jika generateMAC yang dipilih
                console.log("Select Hash Algorithm for MAC Generation:");
                console.log("1. CMAC");
                console.log("2. GMAC-256");
                console.log("3. HMAC-SHA256");

                await new Promise((hashResolve) => {
                    rl.question("Enter the number of the hash algorithm to use: ", (hashAnswer) => {
                        switch (hashAnswer) {
                            case '1':
                                hashAlgo = "CMAC";
                                break;
                            case '2':
                                hashAlgo = "GMAC-256";
                                break;
                            case '3':
                                hashAlgo = "HMAC-SHA256";
                                break;
                            default:
                                console.log("Invalid selection.");
                                process.exit(1);
                        }
                        hashResolve();
                    });
                });
                apiFunction = (payloadSizeKB) => generateMAC(payloadSizeKB, hashAlgo);

            } else if (answer === '3') {
                apiFunctionName = "SealData";
                let algorithm;
                let keyLength;

                // Pilihan untuk Seal Data
                console.log("Choose Algorithm for Sealing:");
                console.log("1. AES");
                console.log("2. RSA");

                await new Promise((sealResolve) => {
                    rl.question("Enter the number of the algorithm to use: ", (sealAnswer) => {
                        switch (sealAnswer) {
                            case '1':
                                algorithm = "AES";
                                console.log("Selected Algorithm: AES");
                                keyLength = 256;
                                break;
                            case '2':
                                algorithm = "RSA";
                                console.log("Selected Algorithm: RSA");

                                // Menentukan panjang kunci untuk RSA
                                console.log("Choose Key Length:");
                                console.log("1. 2048");
                                console.log("2. 3072");
                                console.log("3. 4096");

                                rl.question("Enter the number of the key length to use: ", (keyAnswer) => {
                                    switch (keyAnswer) {
                                        case '1':
                                            keyLength = 2048;
                                            break;
                                        case '2':
                                            keyLength = 3072;
                                            break;
                                        case '3':
                                            keyLength = 4096;
                                            break;
                                        default:
                                            console.log("Invalid selection.");
                                            process.exit(1);
                                    }
                                    sealResolve();
                                });
                                return;
                            default:
                                console.log("Invalid selection.");
                                process.exit(1);
                        }
                        sealResolve();
                    });
                });
                apiFunction = (payloadSizeKB) => sealData(payloadSizeKB, algorithm, keyLength);

            } else if (answer === '4') {
                apiFunctionName = "DataEncryption";
                let algorithm;
                let keyLength;
                let useSessionKey = false;

                // Memilih algoritma enkripsi dan panjang kunci
                console.log("Choose Algorithm for Encryption:");
                console.log("1. AES");
                console.log("2. RSA");

                await new Promise((algoResolve) => {
                    rl.question("Enter the number of the algorithm to use: ", (algoAnswer) => {
                        switch (algoAnswer) {
                            case '1':
                                algorithm = "AES";
                                console.log("Selected Algorithm: AES");
                                keyLength = 256; 
                                break;
                            case '2':
                                algorithm = "RSA";
                                console.log("Selected Algorithm: RSA");

                                // Menentukan panjang kunci untuk RSA
                                console.log("Choose Key Length:");
                                console.log("1. 2048");
                                console.log("2. 3072");
                                console.log("3. 4096");

                                rl.question("Enter the number of the key length to use: ", (keyAnswer) => {
                                    switch (keyAnswer) {
                                        case '1':
                                            keyLength = 2048;
                                            break;
                                        case '2':
                                            keyLength = 3072;
                                            break;
                                        case '3':
                                            keyLength = 4096;
                                            break;
                                        default:
                                            console.log("Invalid selection.");
                                            process.exit(1);
                                    }

                                    // Meminta input untuk useSessionKey jika RSA dipilih
                                    rl.question("Use Session Key? (yes/no): ", (sessionKeyAnswer) => {
                                        useSessionKey = sessionKeyAnswer.toLowerCase() === "yes";
                                        algoResolve();
                                    });
                                });
                                return;
                            default:
                                console.log("Invalid selection.");
                                process.exit(1);
                        }
                        algoResolve();
                    });
                });
                apiFunction = (payloadSizeKB) => encryptData(payloadSizeKB, algorithm, keyLength, useSessionKey);

            } else if (answer === '5') {
                apiFunctionName = "Tokenization";
                // Fungsi untuk Tokenize Data
                apiFunction = (payloadSizeKB) => tokenizeData(payloadSizeKB);

            } else if (answer === '6') {
                apiFunctionName = "DigitalSignatures";
                let algorithm;
                let keyLength;

                // Pilihan untuk Sign Data
                console.log("Choose Algorithm for Signing:");
                console.log("1. ECDSA");
                console.log("2. RSA");

                await new Promise((signResolve) => {
                    rl.question("Enter the number of the algorithm to use: ", (signAnswer) => {
                        switch (signAnswer) {
                            case '1':
                                algorithm = "ECDSA";
                                console.log("Selected Algorithm: ECDSA");
                                break;
                            case '2':
                                algorithm = "RSA";
                                console.log("Selected Algorithm: RSA");

                                // Menentukan panjang kunci untuk RSA
                                console.log("Choose Key Length:");
                                console.log("1. 2048");
                                console.log("2. 3072");
                                console.log("3. 4096");

                                rl.question("Enter the number of the key length to use: ", (keyAnswer) => {
                                    switch (keyAnswer) {
                                        case '1':
                                            keyLength = 2048;
                                            break;
                                        case '2':
                                            keyLength = 3072;
                                            break;
                                        case '3':
                                            keyLength = 4096;
                                            break;
                                        default:
                                            console.log("Invalid selection.");
                                            process.exit(1);
                                    }
                                    signResolve();
                                });
                                return;
                            default:
                                console.log("Invalid selection.");
                                process.exit(1);
                        }
                        signResolve();
                    });
                });
                apiFunction = (payloadSizeKB) => signData(payloadSizeKB, algorithm, keyLength);
            
            } else if (answer === '7') {
                apiFunctionName = "CertificateSignatures";
                let algorithm;
                let keyLength;

                // Meminta parameter untuk Certificate Signing
                console.log("Choose Algorithm for Certificate Signing:");
                console.log("1. ECDSA");
                console.log("2. RSA");

                await new Promise((certResolve) => {
                    rl.question("Enter the number of the algorithm to use: ", (algoAnswer) => {
                        switch (algoAnswer) {
                            case '1':
                                algorithm = "ECDSA";
                                console.log("Selected Algorithm: ECDSA");
                                break;
                            case '2':
                                algorithm = "RSA";
                                console.log("Selected Algorithm: RSA");
                                console.log("Choose Key Length:");
                                console.log("1. 3072");
                                console.log("2. 4096");

                                rl.question("Enter the number of the key length to use: ", (keyAnswer) => {
                                    switch (keyAnswer) {
                                        case '1':
                                            keyLength = 3072;
                                            break;
                                        case '2':
                                            keyLength = 4096;
                                            break;
                                        default:
                                            console.log("Invalid key length selection.");
                                            process.exit(1);
                                    }
                                    certResolve();
                                });
                                return;
                            default:
                                console.log("Invalid algorithm selection.");
                                process.exit(1);
                        }
                        certResolve();
                    });
                });
                apiFunction = () => signCertificate(algorithm, keyLength);

            } else if (answer === '8') {
                apiFunctionName = "KeyInformation";
                let keyId;
                let keyVersion;

                // Meminta parameter untuk Key Information
                await new Promise((keyResolve) => {
                    rl.question("Enter Key ID: ", (keyInput) => {
                        keyId = keyInput.trim();
                        if (!keyId) {
                            console.log("Invalid Key ID. Key ID must be a non-empty string.");
                            process.exit(1);
                        }

                        rl.question("Enter Key Version (optional, press Enter to skip): ", (versionInput) => {
                            keyVersion = versionInput.trim() ? parseInt(versionInput.trim()) : undefined;
                            if (keyVersion !== undefined && (!Number.isInteger(keyVersion) || keyVersion < 0)) {
                                console.log("Invalid Key Version. Must be a non-negative integer.");
                                process.exit(1);
                            }
                            keyResolve();
                        });
                    });
                });
                apiFunction = () => getKeyInfo(keyId, keyVersion);

            } else if (answer === '9') {
                apiFunctionName = "GetSecret";
                // Fungsi untuk Get Secret
                apiFunction = () => getSecret();

            } else if (answer === '10') {
                apiFunctionName = "GenerateKeyPair";
                let algo;
                let algoLength;
                let withCert;
                let wrappingAlgorithm;
                let wrappingKeyLength;

                console.log("Choose Algorithm for Key Pair Generation:");
                console.log("1. RSA");
                console.log("2. ECDSA P-256");

                await new Promise((keypairResolve) => {
                    rl.question("Enter the number of the algorithm to use: ", (algoAnswer) => {
                        switch (algoAnswer) {
                            case '1':
                                algo = "RSA";
                                console.log("Selected Algorithm: RSA");
                                console.log("Choose Key Length:");
                                console.log("1. 2048");
                                console.log("2. 3072");
                                console.log("3. 4096");

                                rl.question("Enter the number of the key length to use: ", (keyLengthAnswer) => {
                                    switch (keyLengthAnswer) {
                                        case '1':
                                            algoLength = 2048;
                                            break;
                                        case '2':
                                            algoLength = 3072;
                                            break;
                                        case '3':
                                            algoLength = 4096;
                                            break;
                                        default:
                                            console.log("Invalid key length selection.");
                                            process.exit(1);
                                    }
                                    keypairResolve();
                                });
                                return;
                            case '2':
                                algo = "ECDSA P-256";
                                algoLength = undefined;
                                keypairResolve();
                                break;
                            default:
                                console.log("Invalid algorithm selection.");
                                process.exit(1);
                        }
                    });
                });

                console.log("Choose Wrapping Algorithm:");
                console.log("1. AES");
                console.log("2. RSA");

                await new Promise((wrapResolve) => {
                    rl.question("Enter the number of the wrapping algorithm to use: ", (wrapAlgoAnswer) => {
                        switch (wrapAlgoAnswer) {
                            case '1':
                                wrappingAlgorithm = "AES";
                                wrappingKeyLength = 256;
                                wrapResolve();
                                break;
                            case '2':
                                wrappingAlgorithm = "RSA";
                                console.log("Choose Wrapping Key Length:");
                                console.log("1. 3072");
                                console.log("2. 4096");

                                rl.question("Enter the number of the wrapping key length to use: ", (wrapKeyAnswer) => {
                                    switch (wrapKeyAnswer) {
                                        case '1':
                                            wrappingKeyLength = 3072;
                                            break;
                                        case '2':
                                            wrappingKeyLength = 4096;
                                            break;
                                        default:
                                            console.log("Invalid wrapping key length selection.");
                                            process.exit(1);
                                    }
                                    wrapResolve();
                                });
                                return;
                            default:
                                console.log("Invalid wrapping algorithm selection.");
                                process.exit(1);
                        }
                    });
                });
                 if (wrappingAlgorithm === "RSA") {
                    await new Promise((keyResolve) => {
                        rl.question("Include Certificate? (yes/no): ", (certAnswer) => {
                            withCert = certAnswer.toLowerCase() === "yes";
                            keyResolve();
                        });
                    });
                 }

                apiFunction = () => externalGenerateKeyPair(algo, algoLength, withCert, wrappingAlgorithm, wrappingKeyLength);

            } else if (answer === '11') {
                apiFunctionName = "GenerateAESKey";

                apiFunction = () => externalGenerateAESKey();
                
            } else if (answer === '12') {
                apiFunctionName = "externalGenerateMAC";
                let hashAlgo;

                // Meminta pilihan hashAlgo jika generateMAC yang dipilih
                console.log("Select Hash Algorithm for MAC Generation:");
                console.log("1. CMAC");
                console.log("2. GMAC-256");
                console.log("3. HMAC-SHA256");

                await new Promise((hashResolve) => {
                    rl.question("Enter the number of the hash algorithm to use: ", (hashAnswer) => {
                        switch (hashAnswer) {
                            case '1':
                                hashAlgo = "CMAC";
                                break;
                            case '2':
                                hashAlgo = "GMAC-256";
                                break;
                            case '3':
                                hashAlgo = "HMAC-SHA256";
                                break;
                            default:
                                console.log("Invalid selection.");
                                process.exit(1);
                        }
                        hashResolve();
                    });
                });
                apiFunction = (payloadSizeKB) => externalGenerateMAC(payloadSizeKB, hashAlgo);

            } else if (answer === '13') {
                apiFunctionName = "externalSealData";
                let algorithm;
                let keyLength;
                let withCert = false;
                let wrappingAlgorithm;
                let wrappingKeyLength;

                console.log("Choose Algorithm for Sealing:");
                console.log("1. AES");
                console.log("2. RSA");

                await new Promise((sealResolve) => {
                    rl.question("Enter the number of the algorithm to use: ", (sealAnswer) => {
                        switch (sealAnswer) {
                            case '1':
                                algorithm = "AES";
                                keyLength = 256;
                                sealResolve();
                                break;
                            case '2':
                                algorithm = "RSA";
                                console.log("Choose Key Length:");
                                console.log("1. 2048");
                                console.log("2. 3072");
                                console.log("3. 4096");

                                rl.question("Enter the number of the key length to use: ", (keyAnswer) => {
                                    switch (keyAnswer) {
                                        case '1':
                                            keyLength = 2048;
                                            break;
                                        case '2':
                                            keyLength = 3072;
                                            break;
                                        case '3':
                                            keyLength = 4096;
                                            break;
                                        default:
                                            console.log("Invalid selection.");
                                            process.exit(1);
                                    }
                                    sealResolve();
                                });
                                return;
                            default:
                                console.log("Invalid selection.");
                                process.exit(1);
                        }
                    });
                });

                if (algorithm === "RSA") {
                    await new Promise((wrapResolve) => {
                        console.log("Choose Wrapping Algorithm:");
                        console.log("1. AES");
                        console.log("2. RSA");

                        rl.question("Enter the number of the wrapping algorithm to use: ", (wrapAlgoAnswer) => {
                            switch (wrapAlgoAnswer) {
                                case '1':
                                    wrappingAlgorithm = "AES";
                                    wrappingKeyLength = 256;
                                    wrapResolve();
                                    break;
                                case '2':
                                    wrappingAlgorithm = "RSA";
                                    console.log("Choose Wrapping Key Length:");
                                    console.log("1. 3072");
                                    console.log("2. 4096");

                                    rl.question("Enter the number of the wrapping key length to use: ", (wrapKeyAnswer) => {
                                        switch (wrapKeyAnswer) {
                                            case '1':
                                                wrappingKeyLength = 3072;
                                                break;
                                            case '2':
                                                wrappingKeyLength = 4096;
                                                break;
                                            default:
                                                console.log("Invalid wrapping key length selection.");
                                                process.exit(1);
                                        }
                                        wrapResolve();
                                    });
                                    return;
                                default:
                                    console.log("Invalid wrapping algorithm selection.");
                                    process.exit(1);
                            }
                        });
                    });

                    if (wrappingAlgorithm === "RSA") {
                        await new Promise((certResolve) => {
                            rl.question("Include Certificate? (yes/no): ", (certAnswer) => {
                                withCert = certAnswer.toLowerCase() === "yes";
                                certResolve();
                            });
                        });
                    }
                }

                apiFunction = (payloadSizeKB) => externalSealData(payloadSizeKB, algorithm, keyLength, withCert, wrappingAlgorithm, wrappingKeyLength);

            } else if (answer === '14') {
                apiFunctionName = "externalEncryptData";
                let algorithm;
                let keyLength;
                let withCert = false;
                let wrappingAlgorithm;
                let wrappingKeyLength;
                let useSessionKey = false;

                console.log("Choose Algorithm for Encryption:");
                console.log("1. AES");
                console.log("2. RSA");

                await new Promise((algoResolve) => {
                    rl.question("Enter the number of the algorithm to use: ", (algoAnswer) => {
                        switch (algoAnswer) {
                            case '1':
                                algorithm = "AES";
                                keyLength = 256;
                                algoResolve();
                                break;
                            case '2':
                                algorithm = "RSA";
                                console.log("Choose Key Length:");
                                console.log("1. 2048");
                                console.log("2. 3072");
                                console.log("3. 4096");

                                rl.question("Enter the number of the key length to use: ", (keyAnswer) => {
                                    switch (keyAnswer) {
                                        case '1':
                                            keyLength = 2048;
                                            break;
                                        case '2':
                                            keyLength = 3072;
                                            break;
                                        case '3':
                                            keyLength = 4096;
                                            break;
                                        default:
                                            console.log("Invalid key length selection.");
                                            process.exit(1);
                                    }

                                    // Meminta input untuk useSessionKey jika RSA dipilih
                                    rl.question("Use Session Key? (yes/no): ", (sessionKeyAnswer) => {
                                        useSessionKey = sessionKeyAnswer.toLowerCase() === "yes";
                                        algoResolve();
                                    });
                                });
                                return;
                            default:
                                console.log("Invalid selection.");
                                process.exit(1);
                        }
                        algoResolve();
                    });
                });

                if (algorithm === "RSA") {
                    await new Promise((wrapResolve) => {
                        console.log("Choose Wrapping Algorithm:");
                        console.log("1. AES");
                        console.log("2. RSA");

                        rl.question("Enter the number of the wrapping algorithm to use: ", (wrapAlgoAnswer) => {
                            switch (wrapAlgoAnswer) {
                                case '1':
                                    wrappingAlgorithm = "AES";
                                    wrappingKeyLength = 256;
                                    wrapResolve();
                                    break;
                                case '2':
                                    wrappingAlgorithm = "RSA";
                                    console.log("Choose Wrapping Key Length:");
                                    console.log("1. 3072");
                                    console.log("2. 4096");

                                    rl.question("Enter the number of the wrapping key length to use: ", (wrapKeyAnswer) => {
                                        switch (wrapKeyAnswer) {
                                            case '1':
                                                wrappingKeyLength = 3072;
                                                break;
                                            case '2':
                                                wrappingKeyLength = 4096;
                                                break;
                                            default:
                                                console.log("Invalid wrapping key length selection.");
                                                process.exit(1);
                                        }
                                        wrapResolve();
                                    });
                                    return;
                                default:
                                    console.log("Invalid wrapping algorithm selection.");
                                    process.exit(1);
                            }
                        });
                    });
                    
                    if (wrappingAlgorithm === "RSA") {
                        await new Promise((certResolve) => {
                            rl.question("Include Certificate? (yes/no): ", (certAnswer) => {
                                withCert = certAnswer.toLowerCase() === "yes";
                                certResolve();
                            });
                        });
                    }
                }

                apiFunction = (payloadSizeKB) => externalEncryptData(payloadSizeKB, algorithm, keyLength, withCert, wrappingAlgorithm, wrappingKeyLength, useSessionKey);

            } else if (answer === '15') {
                apiFunctionName = "externalTokenizeData";

                apiFunction = (payloadSizeKB) => externalTokenizeData(payloadSizeKB);

            } else if (answer === '16') {
                apiFunctionName = "externalSignData";
                let algorithm;
                let keyLength;
                let wrappingAlgorithm;
                let wrappingKeyLength;
                let withCert;

                console.log("Choose Algorithm for Signing:");
                console.log("1. ECDSA P-256");
                console.log("2. RSA");

                await new Promise((signResolve) => {
                    rl.question("Enter the number of the algorithm to use: ", (signAnswer) => {
                        switch (signAnswer) {
                            case '1':
                                algorithm = "ECDSA P-256";
                                keyLength = undefined;
                                signResolve();
                                break;
                            case '2':
                                algorithm = "RSA";
                                console.log("Choose Key Length:");
                                console.log("1. 2048");
                                console.log("2. 3072");
                                console.log("3. 4096");

                                rl.question("Enter the number of the key length to use: ", (keyAnswer) => {
                                    switch (keyAnswer) {
                                        case '1':
                                            keyLength = 2048;
                                            break;
                                        case '2':
                                            keyLength = 3072;
                                            break;
                                        case '3':
                                            keyLength = 4096;
                                            break;
                                        default:
                                            console.log("Invalid key length selection.");
                                            process.exit(1);
                                    }
                                    signResolve();
                                });
                                return;
                            default:
                                console.log("Invalid algorithm selection.");
                                process.exit(1);
                        }
                    });
                });

                console.log("Choose Wrapping Algorithm:");
                console.log("1. AES");
                console.log("2. RSA");

                await new Promise((wrapResolve) => {
                    rl.question("Enter the number of the wrapping algorithm to use: ", (wrapAlgoAnswer) => {
                        switch (wrapAlgoAnswer) {
                            case '1':
                                wrappingAlgorithm = "AES";
                                wrappingKeyLength = 256;
                                wrapResolve();
                                break;
                            case '2':
                                wrappingAlgorithm = "RSA";
                                console.log("Choose Wrapping Key Length:");
                                console.log("1. 3072");
                                console.log("2. 4096");

                                rl.question("Enter the number of the wrapping key length to use: ", (wrapKeyAnswer) => {
                                    switch (wrapKeyAnswer) {
                                        case '1':
                                            wrappingKeyLength = 3072;
                                            break;
                                        case '2':
                                            wrappingKeyLength = 4096;
                                            break;
                                        default:
                                            console.log("Invalid wrapping key length selection.");
                                            process.exit(1);
                                    }
                                    wrapResolve();
                                });
                                return;
                            default:
                                console.log("Invalid wrapping algorithm selection.");
                                process.exit(1);
                        }
                    });
                });

                if (wrappingAlgorithm === "RSA") {
                    await new Promise((certResolve) => {
                        rl.question("Include Certificate? (yes/no):", (certAnswer) => {
                            withCert = certAnswer.toLowerCase() === "yes";
                            certResolve();
                        });
                    });
                }

                apiFunction = (payloadSizeKB) => externalSignData(payloadSizeKB, algorithm, keyLength, wrappingAlgorithm, wrappingKeyLength, withCert);

            } else {
                console.log("Invalid selection.");
                process.exit(1);
            }
            rl.close();
            resolve({ apiFunction, apiFunctionName });
        });
    });
}

// Fungsi untuk menjalankan stress test dan menyimpan hasilnya ke CSV
async function runStressTest(users, payloadSizeKB, apiFunction, apiFunctionName) {
    let successCount = 0;   // Jumlah permintaan yang berhasil
    let totalLatency = 0;   // Total waktu latensi dalam milidetik
    let errorCount = 0;     // Jumlah permintaan yang gagal
    let maxLatency = 0;     // Waktu latensi maksimum yang tercatat
    const startTime = performance.now();  // Waktu mulai uji stres

    const promises = [];

    // Membuat dan menjalankan permintaan untuk setiap pengguna bersamaan
    for (let i = 0; i < users; i++) {
        const startRequestTime = performance.now();  // Waktu mulai setiap permintaan

        promises.push(
            apiFunction(payloadSizeKB).then(() => {
                const endRequestTime = performance.now();  // Waktu selesai permintaan
                const latency = endRequestTime - startRequestTime;
                totalLatency += latency; // Menambahkan latensi ke total
                if (latency > maxLatency) maxLatency = latency; // Memperbarui latensi maksimum jika lebih tinggi
                successCount++;  // Menghitung permintaan yang berhasil
            }).catch(error => {
                const endRequestTime = performance.now();
                const latency = endRequestTime - startRequestTime;
                totalLatency += latency; // Memasukkan latensi untuk permintaan yang gagal
                if (latency > maxLatency) maxLatency = latency;
                errorCount++;  // Menghitung permintaan yang gagal
                console.error(`Error in request ${i + 1}:`, error);  // Menangani error
            })
        );
    }

    // Menunggu semua permintaan selesai
    await Promise.all(promises);

    const endTime = performance.now();  // Waktu selesai uji stres
    const totalTime = (endTime - startTime) / 1000;  // Total waktu eksekusi dalam detik

    // Menghitung throughput (TPS: Transactions per Second)
    const throughput = successCount / totalTime;

    // Menghitung rata-rata latensi
    const avgLatency = successCount > 0 ? totalLatency / successCount : 0;

    // Menghitung error rate (%)
    const errorRate = ((errorCount / users) * 100).toFixed(2);

    // Waktu pengujian untuk CSV
    const testTimestamp = new Date().toISOString();

    // Menyusun data hasil tes untuk CSV
    const result = {
        testTimestamp,
        users,
        payloadSizeKB,
        throughput: throughput.toFixed(2),
        avgLatency: avgLatency.toFixed(2),
        maxLatency: maxLatency.toFixed(2),
        errorRate
    };

    // Menyimpan hasil ke file CSV
    await writeResultsToCSV(result, apiFunctionName);

    // Menampilkan hasil uji stres di console
    console.log(`Stress Test Results - Users: ${users}, Payload Size: ${payloadSizeKB} KB`);
    console.log(`Throughput (TPS): ${result.throughput}`);
    console.log(`Average Latency (ms): ${result.avgLatency}`);
    console.log(`Maximum Latency (ms): ${result.maxLatency}`);
    console.log(`Error Rate (%): ${result.errorRate}`);
    console.log(`-------------------------------------------`);
}

// Fungsi utama untuk memilih dan menjalankan stress test
async function performStressTests(apiFunction, apiFunctionName) {
    const testCases = [
        { users: 10, payloadSizeKB: 0.1 },
        { users: 100, payloadSizeKB: 0.1 },
        { users: 1000, payloadSizeKB: 0.1 },
        { users: 3000, payloadSizeKB: 0.1 },
        { users: 5000, payloadSizeKB: 0.1 },
        { users: 7000, payloadSizeKB: 0.1 },
        { users: 10000, payloadSizeKB: 0.1 },
        { users: 10, payloadSizeKB: 0.2 },
        { users: 100, payloadSizeKB: 0.2 },
        { users: 1000, payloadSizeKB: 0.2 },
        { users: 3000, payloadSizeKB: 0.2 },
        { users: 5000, payloadSizeKB: 0.2 },
        { users: 7000, payloadSizeKB: 0.2 },
        { users: 10000, payloadSizeKB: 0.2 },
        { users: 10, payloadSizeKB: 0.3 },
        { users: 100, payloadSizeKB: 0.3 },
        { users: 1000, payloadSizeKB: 0.3 },
        { users: 3000, payloadSizeKB: 0.3 },
        { users: 5000, payloadSizeKB: 0.3 },
        { users: 7000, payloadSizeKB: 0.3 },
        { users: 10000, payloadSizeKB: 0.3 },
        { users: 10, payloadSizeKB: 0.4 },
        { users: 100, payloadSizeKB: 0.4 },
        { users: 1000, payloadSizeKB: 0.4 },
        { users: 3000, payloadSizeKB: 0.4 },
        { users: 5000, payloadSizeKB: 0.4 },
        { users: 7000, payloadSizeKB: 0.4 },
        { users: 10000, payloadSizeKB: 0.4 },
        { users: 10, payloadSizeKB: 1 },
        { users: 100, payloadSizeKB: 1 },
        { users: 1000, payloadSizeKB: 1 },
        { users: 3000, payloadSizeKB: 1 },
        { users: 5000, payloadSizeKB: 1 },
        { users: 7000, payloadSizeKB: 1 },
        { users: 10000, payloadSizeKB: 1 },
        { users: 10, payloadSizeKB: 100 },
        { users: 100, payloadSizeKB: 100 },
        { users: 1000, payloadSizeKB: 100 },
        { users: 3000, payloadSizeKB: 100 },
        { users: 5000, payloadSizeKB: 100 },
        { users: 7000, payloadSizeKB: 100 },
        { users: 10000, payloadSizeKB: 100 }
    ];

    for (const testCase of testCases) {
        console.log(`Starting stress test with ${testCase.users} users and ${testCase.payloadSizeKB} KB payload.`);
        await runStressTest(testCase.users, testCase.payloadSizeKB, apiFunction, apiFunctionName);
        console.log(`Completed stress test with ${testCase.users} users and ${testCase.payloadSizeKB} KB payload.`);
    }
}

// Fungsi untuk menulis hasil ke file CSV
async function writeResultsToCSV(result, apiFunctionName) {
    const csvHeader = 'API Function,Test Timestamp,Users,Payload Size (KB),Throughput (TPS),Avg Latency (ms),Max Latency (ms),Error Rate (%)\n';
    const csvData = `${apiFunctionName},${result.testTimestamp},${result.users},${result.payloadSizeKB},${result.throughput},${result.avgLatency},${result.maxLatency},${result.errorRate}\n`;

    // Tentukan nama file berdasarkan nama fungsi yang dipilih
    const filename = `stress_test_results.csv`;

    // Cek jika file sudah ada, jika belum, tulis header
    if (!fs.existsSync(filename)) {
        fs.writeFileSync(filename, csvHeader);
    }

    // Menambahkan data hasil uji ke file CSV
    fs.appendFileSync(filename, csvData);
}

// Mulai tes dengan menu pilihan
(async () => {
    try {
        const sessionToken = await login();
        if (sessionToken) {
            console.log("Login successful...");
            const { apiFunction, apiFunctionName } = await selectAPIFunction();
            await performStressTests(apiFunction, apiFunctionName);
        } else {
            console.error("Failed to retrieve session token. Exiting.");
        }
    } catch (error) {
        console.error("An error occurred:", error.message);
    }
})();
