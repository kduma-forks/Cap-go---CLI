import { existsSync, readFileSync, writeFileSync } from 'fs'
import { program } from 'commander'
import ciDetect from 'ci-info';
import * as p from '@clack/prompts';
import { checkLatest } from '../api/update';
import {encryptSourceSodium} from '../api/crypto_sodium';
import {baseKeyPub, baseSigningKey, getLocalConfig} from '../utils';

interface Options {
  key?: string
  keyData?: string
  signingKey?: string
  signingKeyData?: string
}

export const encryptZip = async (zipPath: string, options: Options) => {
  p.intro(`Encryption`);

  await checkLatest();
  const localConfig = await getLocalConfig()

  // write in file .capgo the apikey in home directory

  if (!existsSync(zipPath)) {
    p.log.error(`Error: Zip not found at the path ${zipPath}`);
    program.error('');
  }

  const keyPath = options.key || baseKeyPub
  const signingKeyPath = options.signingKey || baseSigningKey

  let publicKey = options.keyData || "";
  let signingKey = options.signingKeyData || "";

  if (!existsSync(keyPath) && !publicKey) {
    p.log.warning(`Cannot find public key ${keyPath} or as keyData option`);
    p.log.error(`Error: Missing public key`);
    program.error('');

  } else if (existsSync(keyPath)) {
    // open with fs publicKey path
    const keyFile = readFileSync(keyPath)
    publicKey = keyFile.toString()
  }

  if (!existsSync(signingKeyPath) && !signingKey) {
    p.log.warning(`Cannot find signing private key ${signingKeyPath} or as signingKeyData option`);
    p.log.error(`Error: Missing signing key`);
    program.error('');

  } else if (existsSync(signingKeyPath)) {
    // open with fs publicKey path
    const keyFile = readFileSync(signingKeyPath)
    signingKey = keyFile.toString()
  }
  // console.log('signingKey', signingKey)
  // console.log('publicKey', publicKey)

  const zipFile = readFileSync(zipPath)
  const encodedZip = encryptSourceSodium(zipFile, publicKey, signingKey)
  p.log.success(`ivSessionKey: ${encodedZip.ivSessionKey}`);
  // write decodedZip in a file
  writeFileSync(`${zipPath}_encrypted.zip`, encodedZip.encryptedData)
  p.log.success(`Encrypted zip saved at ${zipPath}_encrypted.zip`);
  p.outro(`Done ✅`);
  process.exit()
}
