import { existsSync, readFileSync, writeFileSync } from 'fs'
import { program } from 'commander'
import * as p from '@clack/prompts';
import { decryptSourceSodium } from '../api/crypto_sodium';
import {baseKey, baseKeyPub, baseSigningKey, baseSigningKeyPub, getConfig} from '../utils';
import { checkLatest } from '../api/update';

interface Options {
  key?: string
  keyData?: string
  signingKey?: string
  signingKeyData?: string
}

export const decryptZip = async (zipPath: string, ivsessionKey: string, options: Options) => {
  p.intro(`Decrypt zip file`);
  await checkLatest();
  // write in file .capgo the apikey in home directory

  if (!existsSync(zipPath)) {
    p.log.error(`Zip not found at the path ${zipPath}`);
    program.error('');
  }

  const config = await getConfig();
  const { extConfig } = config.app;

  if (!options.key && !existsSync(baseKey) && !extConfig.plugins?.CapacitorUpdater?.privateKey) {
    p.log.error(`Private Key not found at the path ${baseKey} or in ${config.app.extConfigFilePath}`);
    program.error('');
  }

  if (!options.signingKey && !existsSync(baseSigningKeyPub) && !extConfig.plugins?.CapacitorUpdater?.signingKey) {
    p.log.error(`Private Key not found at the path ${baseSigningKeyPub} or in ${config.app.extConfigFilePath}`);
    program.error('');
  }

  const keyPath = options.key || baseKey
  const signingKeyPath = options.signingKey || baseSigningKeyPub
  // check if publicKey exist

  let privateKey = extConfig?.plugins?.CapacitorUpdater?.privateKey
  let signingKey = extConfig?.plugins?.CapacitorUpdater?.signingKey

  if (!existsSync(keyPath) && !privateKey) {
    p.log.error(`Cannot find public key ${keyPath} or as keyData option or in ${config.app.extConfigFilePath}`);
    program.error('');
  } else if (existsSync(keyPath)) {
    // open with fs publicKey path
    const keyFile = readFileSync(keyPath)
    privateKey = keyFile.toString()
  }

  if (!existsSync(signingKeyPath) && !signingKey) {
    p.log.error(`Cannot find public key ${signingKeyPath} or as signingKeyData option or in ${config.app.extConfigFilePath}`);
    program.error('');
  } else if (existsSync(signingKeyPath)) {
    // open with fs publicKey path
    const keyFile = readFileSync(signingKeyPath)
    signingKey = keyFile.toString()
  }
  // console.log('signingKey', signingKey)
  // console.log('privateKey', privateKey)

  const zipFile = readFileSync(zipPath)

  const decodedZip = decryptSourceSodium(
      zipFile,
      ivsessionKey,
      options.keyData ?? privateKey ?? '',
      options.signingKeyData ?? signingKey ?? ''
  );

  // write decodedZip in a file
  writeFileSync(`${zipPath}_decrypted.zip`, decodedZip)
  p.outro(`Decrypted zip file at ${zipPath}_decrypted.zip`);
  process.exit()
}
