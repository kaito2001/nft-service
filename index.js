const express = require('express');
const bodyParser = require('body-parser');
const nacl = require('tweetnacl');
const naclUtil = require('tweetnacl-util');
const { connect, keyStores, KeyPair } = require('near-api-js');
const crypto = require('crypto');
const dotenv = require('dotenv');

dotenv.config();

const app = express();
app.use(bodyParser.json());

const NETWORK_ID = 'testnet';
const RPC_URL = 'https://rpc.testnet.near.org';
const NFT_CONTRACT_ID = 'nft-vbi.testnet';

// Load private key and account ID
const privateKey = process.env.PRIVATE_KEY;
const accountId = process.env.ACCOUNT_ID;

if (!privateKey || !accountId) {
    throw new Error('Please define PRIVATE_KEY and ACCOUNT_ID in your .env file');
}

const keyPair = KeyPair.fromString(privateKey);
const keyStore = new keyStores.InMemoryKeyStore();
keyStore.setKey(NETWORK_ID, accountId, keyPair);

const nearPromise = connect({
    networkId: NETWORK_ID,
    nodeUrl: RPC_URL,
    keyStore,
});

// Endpoint to get the public key
app.get('/public-key', (req, res) => {
    const publicKey = naclUtil.encodeBase64(nacl.sign.keyPair().publicKey);
    res.json({ publicKey });
});

// Endpoint to generate signature
app.post('/sign', (req, res) => {
    const { course_id, user_address } = req.body;

    if (!course_id || !user_address) {
        return res.status(400).json({ error: 'Missing course_id or user_address!' });
    }

    // TODO check điều kiện xem user có được mint ở db không, nếu có thì cho phép kí

    const inputString = `${course_id}:${user_address}`; // hash dữ liệu
    const message = crypto.createHash('sha256').update(inputString, 'utf8').digest('hex');
    const messageUint8 = naclUtil.decodeUTF8(message);

    // kí dữ liệu
    const signatureUint8 = nacl.sign.detached(messageUint8, nacl.sign.keyPair().secretKey);
    const signature = naclUtil.encodeBase64(signatureUint8);

    res.json({
        message,
        signature,
    });
});

// Endpoint to mint NFT
app.post('/mint-nft', async (req, res) => {
    const { token_id, receiver_id, token_metadata, signature_base64, course_id } = req.body;

    if (!token_id || !receiver_id || !token_metadata || !signature_base64 || !course_id) {
        return res.status(400).json({ error: 'Missing required parameters!' });
    }

    try {
        const near = await nearPromise;
        const account = await near.account(accountId);

        const result = await account.functionCall({
            contractId: NFT_CONTRACT_ID,
            methodName: 'nft_mint',
            args: {
                token_id,
                receiver_id,
                token_metadata,
                signature_base64,
                course_id,
            },
            gas: '300000000000000', // Adjust gas
            attachedDeposit: '1000000000000000000000000', // Attach necessary deposit
        });

        res.json({
            success: true,
            transaction: result,
        });
    } catch (error) {
        res.status(500).json({
            success: false,
            error: error.message,
        });
    }
});

const PORT = 3000;
app.listen(PORT, () => {
    console.log(`Server running at http://localhost:${PORT}`);
});
