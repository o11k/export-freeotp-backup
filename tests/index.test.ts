/// <reference types="jest" />
/// <reference types="node" />

import fs from 'node:fs';

import exportFreeOTPBackup from '../src/index'

const PATH_DIR = "tests/backups";

test("sanity", async () => {
    const data = new Uint8Array(fs.readFileSync(PATH_DIR + "/externalBackup-demo.xml"));
    const uris = await exportFreeOTPBackup(data, "demo");
    expect(uris).toEqual(["otpauth://totp/Demo%20Label?secret=AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA&issuer=Demo+Issuer"]);
})
