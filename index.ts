// 1. 用户端创建 dogecoin 交易
// 1-1. 使用 p2sh, 使用 relayer 的公钥和用户的 ethAddress 构建脚本地址
// 1-2. 直接向 1-1 构建的地址进行转账
// 1-3, 获取 1-2 转账的 txHash 结果

import BIP32Factory from "bip32";
import * as ecc from "@bitcoin-js/tiny-secp256k1-asmjs";
import * as bip39 from "bip39";
import * as bitcoin from "bitcoinjs-lib";
import ECPairFactory, { ECPairInterface, Signer } from "ecpair";
import Client from "bitcoin-core";
import { PsbtInput } from "bip174/src/lib/interfaces";

const BIP32 = BIP32Factory(ecc);
const ECPair = ECPairFactory(ecc);
bitcoin.initEccLib(ecc);

const client = new Client({
    network: "regtest",
    host: "ec2-3-15-141-150.us-east-2.compute.amazonaws.com",
    port: 18333,
    username: "111111",
    password: "111111"
});

async function testConnection() {
    try {
      const blockchainInfo = await client.getBlockchainInfo();
      console.log('Blockchain Info:', blockchainInfo.chain);
    } catch (error) {
      console.error('Error connecting to the Dogecoin node:', error.message);
    }
  }
  
 
const dogecoinNetwork = {
    messagePrefix: '\x19Dogecoin Signed Message:\n',
    bech32: "doge",
    bip32: {
      public: 0x0432a9a8,
      private: 0x0432a243
    },
    pubKeyHash: 0x6f, // Regtest P2PKH 地址前缀 'n' or m
    scriptHash: 0xc4, // Regtest P2SH 地址前缀 '2'
    wif: 0xef,        // Regtest WIF 私钥前缀 9 or c
    dustThreshold: 0  // 最小 dust 限制为 0
  };

const ethAddress = "0x1234567890abcdef1234567890abcdef12345678";

const mnemonic = "doge doge doge doge doge doge doge doge doge doge doge doge";
// 用助记词生成 relayer keypair
async function deriveKeyPairFromMnemonic(mnemonic: string) {
    const seed = await bip39.mnemonicToSeed(mnemonic);
    const root = BIP32.fromSeed(seed, dogecoinNetwork);
    
    const path = "m/44'/3'/0'/0/0";
    const child = root.derivePath(path);

    // Get the address from child
    const { address } = bitcoin.payments.p2pkh({
        pubkey: Buffer.from(child.publicKey),
        network: dogecoinNetwork
    });

    return {
        privateKey: Buffer.from(child.privateKey!).toString('hex'),
        publicKey: Buffer.from(child.publicKey).toString('hex'),
        wif: child.toWIF(),
        keyPair: ECPair.fromPrivateKey(child.privateKey!, { network: dogecoinNetwork }),
        keyPairFromWIF: ECPair.fromWIF(child.toWIF(), dogecoinNetwork),
        child: child,
        address: address,
    };
}

function createDogecoinTransaction(relayerPubKey: string, ethAddress: string) {
    const ethAddressBytes = Buffer.from(ethAddress.slice(2), "hex");
    const relayerPubKeyBytes = Buffer.from(relayerPubKey, "hex");
    const redeemScript = bitcoin.script.compile([
        ethAddressBytes,
        bitcoin.opcodes.OP_EQUALVERIFY,
        relayerPubKeyBytes,
        bitcoin.opcodes.OP_CHECKSIG,
    ]);

    const p2sh = bitcoin.payments.p2sh({
        network: dogecoinNetwork,
        redeem: { output: redeemScript },
    });

    const p2shAddress = p2sh.address;

    return p2shAddress;
}

async function useSendTransaction(address: string) {
    try {
        // 发送 5 个币到指定地址
        const tx = await client.sendToAddress(address, 5);
        console.log('Transaction sent successfully:', tx);
        return tx;
    } catch (error) {
        console.error('Error sending transaction:', error);
        throw error;
    }
}

async function relayerUnlockUtxo(txHash: string, keyPair: ECPairInterface, reciveAddress: string) {
    const tx = await getTransaction(txHash);
    console.log(tx);

    const rawTx = tx.hex;
    const txDetails = bitcoin.Transaction.fromHex(rawTx);

    // Extract the redeem script from the scriptPubKey
    const redeemScript = bitcoin.script.compile([
        Buffer.from(ethAddress.slice(2), "hex"),
        bitcoin.opcodes.OP_EQUALVERIFY,
        Buffer.from(keyPair.publicKey),
        bitcoin.opcodes.OP_CHECKSIG,
    ]);

    const psbt = new bitcoin.Psbt({ network: dogecoinNetwork });
    
    // Get actual value from the UTXO
    const utxoValue = txDetails.outs[0].value;
    
    psbt.addInput({
        hash: txHash,
        index: 0,
        nonWitnessUtxo: Buffer.from(tx.hex, 'hex'),
        redeemScript: redeemScript,
    });

    // Calculate output value by subtracting fee
    const fee = 1000000; // 0.01 DOGE fee in satoshis (降低手续费)
    const outputValue = utxoValue - fee;
    
    psbt.addOutput({
        address: reciveAddress,
        value: outputValue, // Use calculated output value
    });
    console.log('relayer send to', reciveAddress, outputValue)
    // await new Promise(resolve => setTimeout(resolve, 1000));
    console.log('signInput 0...')
    psbt.signInput(0, {
        publicKey: Buffer.from(keyPair.publicKey),
        sign: (hash: Buffer) => Buffer.from(keyPair.sign(hash))
    });
    // psbt.signInput(0, keyPair as any)
    console.log('signInput 0 done')
    console.log('finalizeInput 0...')
    // psbt.finalizeAllInputs();
    psbt.finalizeInput(0, (
        inputIndex: number,
        input: PsbtInput,
        script: Buffer
    ) => {
        const payment = bitcoin.payments.p2sh({
            network: dogecoinNetwork,
            redeem: { 
                network: dogecoinNetwork,
                input: bitcoin.script.compile([
                    input.partialSig![0].signature,
                    Buffer.from(ethAddress.slice(2), "hex"),
                ]),
                output: redeemScript,
            },
        });

        return {
            finalScriptSig: payment.input,
            finalScriptWitness: undefined
        };
    });
    console.log('finalizeInput 0 done')
    const signedTx = psbt.extractTransaction().toHex();
    console.log('Signed Transaction:', signedTx);

    const txId = await client.sendRawTransaction(signedTx);
    console.log('Transaction sent successfully:', txId);
}

async function getTransaction(txHash: string) {
    const tx = await client.getTransaction(txHash);
    return tx;
}

async function mineBlock(num: number) {
    await client.generate(num);
    console.log(`Mined ${num} blocks`);
}

// 2. relayer 端解析 txHash
// 2-1. 解析 txHash 获取脚本中的 ethAddress
// 2-2. 使用 relayer 私钥对 交易信息的 utxo 进行解锁
// 2-3. 把 2-2 中解锁的资金转向到一个固定地址中。（relayer 的地址）


async function run() {
    
    await testConnection();

    // 1. generate the relayer keyPair
    const { publicKey, keyPair, child, address } = await deriveKeyPairFromMnemonic(mnemonic);
    
    // 2. generate the anyWhereAddress from relayer publicKey and user's ethAddress
    const anyWhereAddress = createDogecoinTransaction(publicKey, ethAddress);
    // 3. user send coin to anyWhereAddress then get the txHash
    console.log('anyWhereAddress', anyWhereAddress)
    // return console.log(publicKey)
    const txHash = await useSendTransaction(anyWhereAddress as string);
    // 4. mine a block
    await mineBlock(10);
    // console.log(txHash) // 5421526d63538822a1735b2a14a787ebece9b7d73ccc37aa76bff655997eb2a2

    // 5. relayer parse txHash for user's ethAddress
    // 5421526d63538822a1735b2a14a787ebece9b7d73ccc37aa76bff655997eb2a2
    await relayerUnlockUtxo(txHash, keyPair, address as string); 
    await mineBlock(10);

    // 5. relayer use his privateKey to unlock the utxo and send the fund to his address

    
}

run().then(() => {
    console.log("done");
});