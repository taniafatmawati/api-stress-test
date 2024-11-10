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

// Fungsi untuk login dan mendapatkan session token
async function login() {
    try {
        // console.log("Attempting to login with the following parameters:");
        // console.log("URL:", process.env.URL_SGKMS);
        // console.log("Slot ID:", process.env.SLOT_ID);
        // console.log("Password:", process.env.PASSWORD_SGKMS);

        // console.log("Payload for login:", JSON.stringify(payload));

        const response = await axios.post(`${process.env.URL_SGKMS}/v1.0/agent/login`, { 
            slotId: parseInt(process.env.SLOT_ID),
            password: process.env.PASSWORD_SGKMS 
        }, {
            headers: { 'Content-Type': 'application/json' },
            httpsAgent: agent
        });

        // console.log("Login Response:", JSON.stringify(response.data, null, 2));

        // Mengecek apakah sessionToken ada dalam response
        if (response.data && response.data.result && response.data.result.sessionToken) {
            // console.log("Session Token Retrieved:", response.data.result.sessionToken);
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

// Fungsi untuk melakukan tanda tangan (signing) data
async function signData(sessionToken, payloadSizeKB, algorithm, keyLength) {
    try {
        const payload = generatePayload(payloadSizeKB); 
        const keyId = getKeyIdSign(algorithm, keyLength); 

        if (!keyId) {
            throw new Error(`Key ID tidak ditemukan untuk algoritma ${algorithm} dengan panjang kunci ${keyLength}`);
        }

        // Menampilkan log parameter yang akan digunakan (optional)
        // console.log("Attempting sign with the following parameters:");
        // console.log("Session Token:", sessionToken);
        // console.log("Slot ID:", parseInt(process.env.SLOT_ID));
        // console.log("Key ID:", keyId);
        // console.log("Payload:", payload);

        const response = await axios.post(`${process.env.URL_SGKMS}/v1.0/sign`, {
            sessionToken: sessionToken,
            slotId: parseInt(process.env.SLOT_ID),
            keyId: keyId,
            data: payload
        }, {
            headers: { 'Content-Type': 'application/json' },
            httpsAgent: agent
        });
        // console.log('Sign response:', JSON.stringify(response.data, null, 2));
        return response.data;
    } catch (error) {
        console.error("Sign operation failed:", error.response ? error.response.data : error.message);
        throw error;
    }
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

// Fungsi untuk enkripsi data
async function encryptData(sessionToken, payloadSizeKB, algorithm, keyLength, useSessionKey) {
    try {
        const payload = generatePayload(payloadSizeKB); // Data dibuat dari generatePayload
        const keyId = getKeyIdEncrypt(algorithm, keyLength); // Mendapatkan keyId berdasarkan algoritma dan panjang kunci

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

        // console.log("Attempting encryption with the following parameters:");
        // console.log("Session Token:", sessionToken);
        // console.log("Slot ID:", parseInt(process.env.SLOT_ID));
        // console.log("Key ID:", keyId);
        // console.log("Use Session Key:", useSessionKey);
        // console.log("Plaintext:", JSON.stringify(plaintext, null, 2));

        const response = await axios.post(`${process.env.URL_SGKMS}/v1.0/encrypt`, {
            sessionToken: sessionToken,
            slotId: parseInt(process.env.SLOT_ID),
            keyId: keyId,
            useSessionKey: algorithm === "AES" ? undefined : useSessionKey,
            plaintext: plaintext
        }, {
            headers: { 'Content-Type': 'application/json' },
            httpsAgent: agent
        });
        // console.log("Encrypt response:", JSON.stringify(response.data, null, 2));
        return response.data;
    } catch (error) {
        console.error("Encryption failed:", error.response ? error.response.data : error.message);
        throw error;
    }
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

// Fungsi untuk melakukan seal (enkripsi) data dengan metadata
async function sealData(sessionToken, payloadSizeKB, algorithm, keyLength) {
    try {
        const payload = generatePayload(payloadSizeKB); // Data payload dihasilkan dari generatePayload
        const keyId = getKeyIdSeal(algorithm, keyLength); // Mendapatkan keyId berdasarkan algoritma dan panjang kunci

        if (!keyId) {
            throw new Error(`Key ID tidak ditemukan untuk algoritma ${algorithm} dengan panjang kunci ${keyLength}`);
        }

        // Konfigurasi array plaintext
        const plaintext = [payload];

        // Menampilkan log parameter yang akan digunakan
        // console.log("Attempting sealing with the following parameters:");
        // console.log("Session Token:", sessionToken);
        // console.log("Slot ID:", parseInt(process.env.SLOT_ID));
        // console.log("Key ID:", keyId);
        // console.log("Plaintext:", JSON.stringify(plaintext, null, 2));

        const response = await axios.post(`${process.env.URL_SGKMS}/v1.0/seal`, {
            sessionToken: sessionToken,
            slotId: parseInt(process.env.SLOT_ID),
            keyId: keyId,
            plaintext: plaintext
        }, {
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

// Fungsi untuk generate MAC (Message Authentication Code)
async function generateMAC(sessionToken, payloadSizeKB, hashAlgo) {
    try {
        const data = generatePayload(payloadSizeKB); // Data dibuat dari generatePayload
        const maxDataSize = 700; // Maksimum ukuran data dalam byte (700 KB)

        // Validasi ukuran data
        if (payloadSizeKB > maxDataSize) {
            throw new Error("Data size exceeds the maximum limit of 700 KB");
        }

        // Validasi nilai hashAlgo
        const validHashAlgos = ["CMAC", "GMAC-256", "HMAC-SHA256"];
        if (!validHashAlgos.includes(hashAlgo)) {
            throw new Error(`Invalid hash algorithm. Please choose one of: ${validHashAlgos.join(", ")}`);
        }

        // console.log("Attempting MAC generation with the following parameters:");
        // console.log("Session Token:", sessionToken);
        // console.log("Slot ID:", parseInt(process.env.SLOT_ID));
        // console.log("Key ID:", process.env.KEY_ID_MAC);
        // console.log("Hash Algorithm:", hashAlgo);
        // console.log("Data:", data);

        const response = await axios.post(`${process.env.URL_SGKMS}/v1.0/mac/generate`, {
            sessionToken: sessionToken,
            slotId: parseInt(process.env.SLOT_ID),
            keyId: process.env.KEY_ID_MAC,
            hashAlgo: hashAlgo,
            data: data
        }, {
            headers: { 'Content-Type': 'application/json' },
            httpsAgent: agent
        });
        // console.log("MAC Generate response:", JSON.stringify(response.data, null, 2));
        return response.data;
    } catch (error) {
        console.error("MAC Generation failed:", error.response ? error.response.data : error.message);
        throw error;
    }
}

// Fungsi untuk mengambil secret dari SG-KMS
async function getSecret(sessionToken) {
    try {
        // console.log("Attempting to retrieve secret with the following parameters:");
        // console.log("Session Token:", sessionToken);
        // console.log("Slot ID:", parseInt(process.env.SLOT_ID));
        // console.log("Secret ID:", process.env.SECRET_ID);

        const response = await axios.post(`${process.env.URL_SGKMS}/v1.0/secret/get`, {
            sessionToken: sessionToken,
            slotId: parseInt(process.env.SLOT_ID),
            secretId: process.env.SECRET_ID
        }, {
            headers: { 'Content-Type': 'application/json' },
            httpsAgent: agent
        });

        // console.log("Secret Retrieve Response:", JSON.stringify(response.data, null, 2));
        return response.data;
    } catch (error) {
        console.error("Secret retrieval failed:", error.response ? error.response.data : error.message);
        throw error;
    }
}

// Fungsi untuk melakukan tokenisasi data dengan format yang disesuaikan
async function tokenizeData(sessionToken, payloadSizeKB) {
    try {
        const textPayload = generatePayload(payloadSizeKB);
        const formatChar = generateFormatChar(textPayload);

        // Validasi panjang textPayload dan formatChar
        if (textPayload.length !== formatChar.length) {
            throw new Error("Text and formatChar must have the same length.");
        }

        const keyId = process.env.KEY_ID_TOKENIZE; // Key ID untuk tokenisasi

        // Menampilkan log parameter yang akan digunakan
        // console.log("Attempting tokenization with the following parameters:");
        // console.log("Session Token:", sessionToken);
        // console.log("Slot ID:", parseInt(process.env.SLOT_ID));
        // console.log("Key ID:", keyId);
        // console.log("Plaintext:", JSON.stringify({ text: textPayload, formatChar: formatChar }, null, 2));

        const response = await axios.post(`${process.env.URL_SGKMS}/v1.0/tokenize`, {
            sessionToken: sessionToken,
            slotId: parseInt(process.env.SLOT_ID),
            keyId: keyId,
            plaintext: [{
                text: textPayload,
                formatChar: formatChar
            }]
        }, {
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

// Menu untuk memilih fungsi API
async function selectAPIFunction() {
    return new Promise((resolve) => {
        const rl = readline.createInterface({
            input: process.stdin,
            output: process.stdout
        });

        console.log("Select API Function for Stress Test:");
        console.log("1. MAC Generate");
        console.log("2. Encrypt");
        console.log("3. Seal Data");
        console.log("4. Get Secret");
        console.log("5. Tokenize Data");
        console.log("6. Sign");

        rl.question("Enter the number of the function to test: ", async (answer) => {
            let apiFunction;
            let apiFunctionName;

            if (answer === '1') {
                apiFunctionName = "MACGenerate";
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
                apiFunction = (sessionToken, payloadSizeKB) => generateMAC(sessionToken, payloadSizeKB, hashAlgo);
            
            } else if (answer === '2') {
                apiFunctionName = "Encrypt";
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
                                keyLength = 256; // AES menggunakan panjang kunci 256
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
                apiFunction = (sessionToken, payloadSizeKB) => encryptData(sessionToken, payloadSizeKB, algorithm, keyLength, useSessionKey);   
            
            } else if (answer === '3') {
                apiFunctionName = "Seal";
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
                apiFunction = (sessionToken, payloadSizeKB) => sealData(sessionToken, payloadSizeKB, algorithm, keyLength);

            } else if (answer === '4') {
                apiFunctionName = "GetSecret";
                // Fungsi untuk Get Secret
                apiFunction = (sessionToken) => getSecret(sessionToken);

            } else if (answer === '5') {
                apiFunctionName = "TokenizeData";
                // Fungsi untuk Tokenize Data
                apiFunction = (sessionToken, payloadSizeKB) => tokenizeData(sessionToken, payloadSizeKB);

            } else if (answer === '6') {
                apiFunctionName = "Sign";
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
                apiFunction = (sessionToken, payloadSizeKB) => signData(sessionToken, payloadSizeKB, algorithm, keyLength);
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
async function runStressTest(sessionToken, users, payloadSizeKB, apiFunction, apiFunctionName) {
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
            apiFunction(sessionToken, payloadSizeKB).then(() => {
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

// Fungsi untuk menulis hasil ke file CSV
async function writeResultsToCSV(result, apiFunctionName) {
    const csvHeader = 'Test Timestamp,Users,Payload Size (KB),Throughput (TPS),Avg Latency (ms),Max Latency (ms),Error Rate (%)\n';
    const csvData = `${result.testTimestamp},${result.users},${result.payloadSizeKB},${result.throughput},${result.avgLatency},${result.maxLatency},${result.errorRate}\n`;

    // Tentukan nama file berdasarkan nama fungsi yang dipilih
    const filename = `stress_test_results_${apiFunctionName}.csv`;

    // Cek jika file sudah ada, jika belum, tulis header
    if (!fs.existsSync(filename)) {
        fs.writeFileSync(filename, csvHeader);
    }

    // Menambahkan data hasil uji ke file CSV
    fs.appendFileSync(filename, csvData);
}

// Fungsi utama untuk memilih dan menjalankan stress test
async function performStressTests(sessionToken, apiFunction, apiFunctionName) {
    const testCases = [
        // { users: 10, payloadSizeKB: 0.1 },
        // { users: 20, payloadSizeKB: 0.1 },
        // { users: 50, payloadSizeKB: 0.1 },
        // { users: 100, payloadSizeKB: 0.1 },
        // { users: 500, payloadSizeKB: 0.1 },
        // { users: 1000, payloadSizeKB: 0.1 },
        // { users: 2000, payloadSizeKB: 0.1 },
        // { users: 3000, payloadSizeKB: 0.1 },
        // { users: 10, payloadSizeKB: 0.3 },
        // { users: 20, payloadSizeKB: 0.3 },
        // { users: 50, payloadSizeKB: 0.3 },
        // { users: 100, payloadSizeKB: 0.3 },
        // { users: 500, payloadSizeKB: 0.3 },
        // { users: 1000, payloadSizeKB: 0.3 },
        // { users: 2000, payloadSizeKB: 0.3 },
        // { users: 3000, payloadSizeKB: 0.3 },
        // { users: 10, payloadSizeKB: 0.5 },
        // { users: 20, payloadSizeKB: 0.5 },
        // { users: 50, payloadSizeKB: 0.5 },
        // { users: 100, payloadSizeKB: 0.5 },
        // { users: 500, payloadSizeKB: 0.5 },
        // { users: 1000, payloadSizeKB: 0.5 },
        // { users: 2000, payloadSizeKB: 0.5 },
        // { users: 3000, payloadSizeKB: 0.5 },
        // { users: 10, payloadSizeKB: 1 },
        // { users: 20, payloadSizeKB: 1 },
        // { users: 50, payloadSizeKB: 1 },
        // { users: 100, payloadSizeKB: 1 },
        // { users: 500, payloadSizeKB: 1 },
        // { users: 1000, payloadSizeKB: 1 },
        // { users: 2000, payloadSizeKB: 1 },
        // { users: 3000, payloadSizeKB: 1 },
        // { users: 10, payloadSizeKB: 10 },
        // { users: 20, payloadSizeKB: 10 },
        // { users: 50, payloadSizeKB: 10 },
        // { users: 100, payloadSizeKB: 10 },
        // { users: 500, payloadSizeKB: 10 },
        // { users: 1000, payloadSizeKB: 10 },
        // { users: 2000, payloadSizeKB: 10 },
        // { users: 3000, payloadSizeKB: 10 },
        // { users: 10, payloadSizeKB: 50 },
        // { users: 20, payloadSizeKB: 50 },
        // { users: 50, payloadSizeKB: 50 },
        // { users: 100, payloadSizeKB: 50 },
        // { users: 500, payloadSizeKB: 50 },
        // { users: 1000, payloadSizeKB: 50 },
        // { users: 2000, payloadSizeKB: 50 },
        // { users: 3000, payloadSizeKB: 50 },
        { users: 4000, payloadSizeKB: 1 },
        { users: 5000, payloadSizeKB: 1 },
        { users: 7000, payloadSizeKB: 1 },
        { users: 10000, payloadSizeKB: 1 },
        { users: 15000, payloadSizeKB: 1 },
        { users: 25000, payloadSizeKB: 1 },
        { users: 4000, payloadSizeKB: 10 },
        { users: 5000, payloadSizeKB: 10 },
        { users: 7000, payloadSizeKB: 10 },
        { users: 10000, payloadSizeKB: 10 },
        { users: 15000, payloadSizeKB: 10 },
        { users: 4000, payloadSizeKB: 50 },
        { users: 5000, payloadSizeKB: 50 },
        { users: 7000, payloadSizeKB: 50 },
        { users: 10000, payloadSizeKB: 50 },
        { users: 15000, payloadSizeKB: 50 },
        { users: 4000, payloadSizeKB: 70 },
        { users: 5000, payloadSizeKB: 70 },
        { users: 7000, payloadSizeKB: 70 },
        { users: 10000, payloadSizeKB: 70 },
        { users: 15000, payloadSizeKB: 70 }
    ];

    for (const testCase of testCases) {
        console.log(`Starting stress test with ${testCase.users} users and ${testCase.payloadSizeKB} KB payload.`);
        await runStressTest(sessionToken, testCase.users, testCase.payloadSizeKB, apiFunction, apiFunctionName);
        console.log(`Completed stress test with ${testCase.users} users and ${testCase.payloadSizeKB} KB payload.`);
    }
}

// Mulai tes dengan menu pilihan
(async () => {
    try {
        const sessionToken = await login();
        if (sessionToken) {
            console.log("Login successful...");
            const { apiFunction, apiFunctionName } = await selectAPIFunction();
            await performStressTests(sessionToken, apiFunction, apiFunctionName);
        } else {
            console.error("Failed to retrieve session token. Exiting.");
        }
    } catch (error) {
        console.error("An error occurred:", error.message);
    }
})();
