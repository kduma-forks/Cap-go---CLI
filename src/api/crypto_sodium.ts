import sodium from 'sodium-native';

export interface SodiumKeys {
    publicKey: string,
    privateKey: string
}
export const createSodium = (): SodiumKeys => {
    let publicKey = Buffer.alloc(sodium.crypto_box_PUBLICKEYBYTES)
    let privateKey = Buffer.alloc(sodium.crypto_box_SECRETKEYBYTES)
    sodium.crypto_box_keypair(publicKey, privateKey)

    return {
        publicKey: publicKey.toString('base64'),
        privateKey: privateKey.toString('base64'),
    }
}

export interface EncodedSodium {
    ivSessionKey: string,
    encryptedData: Buffer
}
export const encryptSourceSodium = (source: Buffer, appPublicKey: string, signingPrivateKey: string): EncodedSodium => {
    let pk = Buffer.from(appPublicKey, 'base64');
    let sk = Buffer.from(signingPrivateKey, 'base64');
    let mac = Buffer.alloc(sodium.crypto_box_MACBYTES);
    let nounce= Buffer.alloc(sodium.crypto_box_NONCEBYTES);
    sodium.randombytes_buf(nounce)

    let encryptedData = Buffer.alloc(source.length);
    sodium.crypto_box_detached(encryptedData, mac, source, nounce, pk, sk);

    const ivSessionKey = `${nounce.toString('base64')}:${mac.toString('base64')}`

    return {
        encryptedData,
        ivSessionKey
    }
}

export const decryptSourceSodium = (source: Buffer, sessionKey: string, appPrivateKey: string, signingPublicKey: string): Buffer => {
    let sk = Buffer.from(appPrivateKey, 'base64');
    let pk = Buffer.from(signingPublicKey, 'base64');

    const [nounceString, macString] = sessionKey.split(':');
    let mac = Buffer.from(macString, 'base64');
    let nounce= Buffer.from(nounceString, 'base64');

    let decryptedData = Buffer.alloc(source.length);
    let bool = sodium.crypto_box_open_detached(decryptedData, source, mac, nounce, pk, sk)

    if(!bool) {
        throw new Error("decription failed!")
    }

    return decryptedData
}

// //  test Sodium
//
// const source = 'Hello world'
// console.log('\nsource', source)
// const pair1 = createSodium()
// const pair2 = createSodium()
//
// console.log('\nencryptSource ================================================================')
// //  convert source to base64
// const sourceBuff = Buffer.from(source)
// const res = encryptSourceSodium(sourceBuff, pair1.publicKey, pair2.privateKey)
// console.log('\nencryptedData', res.encryptedData.toString('base64'))
// console.log('\nres', res)
// console.log('\ndecryptSource ================================================================')
// const decodedSource = decryptSourceSodium(res.encryptedData, res.ivSessionKey, pair1.privateKey, pair2.publicKey)
// // convert decodedSource from base64 to utf-8
// const decodedSourceString = decodedSource.toString('utf-8')
// console.log('\ndecodedSourceString', decodedSourceString)
// console.log('\n Is match', decodedSourceString === source)