import ObjectInputStream from 'object-input-stream';

export type BackupFile = {
    masterKey: MasterKey,
    tokens: EncryptedToken[],
}

export type EncryptedToken = {
    key: EncryptedKey,
    token: Token,
}

export type MasterKey = {
    mEncryptedKey: EncryptedKey,
    mAlgorithm: string,
    mIterations: number,
    mSalt: number[],
}

export type EncryptedKey = {
    mCipherText: number[],
    mParameters: number[],
    mCipher: string,
    mToken: string,
}

export type Token = {
    type: "HOTP" | "TOTP",
    issuerExt?: string,
    label: string,

    issuerInt?: string,
    issuerAlt?: string,
    labelAlt?: string,

    algo?: "SHA1" | "SHA256" | "SHA512",

    counter?: number,
    period?: number,
    digits?: number,

    lock?: boolean,
    image?: string,
    color?: string,
}

export function parseBackupFile(data: Uint8Array): BackupFile {
    let map: Map<unknown, unknown>;

    try {
        const ois = new ObjectInputStream(data);
        map = ois.readObject();
    } catch (e) {
        throw new Error("Backup file is not a valid Java object stream containing an object: " + e);
    }

    if (!(map instanceof Map))
        throw new Error("Object from backup file is not a Map");

    const strMap = new Map<string, string>();
    for (const [k, v] of map) {
        if (typeof k !== "string")
            throw new Error("Key from backup file is not a string: " + k);
        if (typeof v !== "string")
            throw new Error("Value from backup file is not a string: " + v);
        strMap.set(k, v);
    }

    if (!strMap.has("masterKey"))
        throw new Error("Master key missing from backup file");

    const strMasterKey = strMap.get("masterKey")!;
    strMap.delete("masterKey");

    const rawTokens: {key: unknown, token: unknown}[] = [];
    const tokenUUIDs = [...strMap.keys()].filter(k => !k.endsWith("-token"));
    for (const uuid of tokenUUIDs) {
        if (!strMap.has(uuid + "-token"))
            throw new Error("Missing token data for key. UUID="+uuid);
        const key = strMap.get(uuid)!;
        const token = strMap.get(uuid + "-token")!;
        strMap.delete(uuid);
        strMap.delete(uuid + "-token");
        rawTokens.push({key, token});
    }
    if (strMap.size > 0)
        throw new Error("Backup file contains corrupted tokens: " + [...strMap.keys()].join(", "));

    const masterKey = validateMasterKey(strMasterKey);
    const tokens = rawTokens.map(({token, key}) => ({
        token: validateToken(token),
        key: validateEncryptedKey(key)}
    ));

    return {masterKey, tokens};
}

function validateMasterKey(raw: unknown, json=true): MasterKey {
    if (json) {
        if (typeof raw !== "string")
            throw new Error("Invalid serialized MasterKey");
        try {
            raw = JSON.parse(raw)
        } catch (e) {
            throw new Error("Serialized MasterKey is not valid JSON: " + e);
        }
    }

    if (typeof raw !== "object" || raw === null
        || !("mEncryptedKey" in raw)
        || !("mAlgorithm" in raw)
        || !("mIterations" in raw)
        || !("mSalt" in raw)
    ) {
        throw new Error("Invalid MasterKey structure");
    }

    let mEncryptedKey;
    try {
        mEncryptedKey = validateEncryptedKey(raw.mEncryptedKey, false);
    } catch (e) {
        throw new Error("Invalid MasterKey.mEncryptedKey: " + e);
    }

    if (typeof raw.mAlgorithm !== "string")
        throw new Error("Invalid MasterKey.mAlgorithm");
    if (typeof raw.mIterations !== "number")
        throw new Error("Invalid MasterKey.mIterations");
    if (!(Array.isArray(raw.mSalt)) || !raw.mSalt.every(item => typeof item === "number"))
        throw new Error("Invalid MasterKey.mSalt");

    return {
        mEncryptedKey,
        mAlgorithm: raw.mAlgorithm,
        mIterations: raw.mIterations,
        mSalt: raw.mSalt,
    }
}

function validateEncryptedKey(raw: unknown, json=true): EncryptedKey {
    if (json) {
        if (typeof raw !== "string")
            throw new Error("Invalid serialized EncryptedKey");
        try {
            raw = JSON.parse(raw)
        } catch (e) {
            throw new Error("Serialized EncryptedKey is not valid JSON: " + e);
        }
        if (typeof raw !== "object" || raw === null || !("key" in raw))
            throw new Error("Invalid serialized inner EncryptedKey");
        raw = raw.key;
        if (typeof raw !== "string")
            throw new Error("Invalid serialized inner EncryptedKey");
        try {
            raw = JSON.parse(raw)
        } catch (e) {
            throw new Error("Serialized inner EncryptedKey is not valid JSON: " + e);
        }
    }

    if (typeof raw !== "object" || raw === null
        || !("mCipherText" in raw)
        || !("mParameters" in raw)
        || !("mCipher" in raw)
        || !("mToken" in raw)
    ) {
        throw new Error("Invalid EncryptedKey structure");
    }

    if (!Array.isArray(raw.mCipherText) || !raw.mCipherText.every(item => typeof item === "number"))
        throw new Error("Invalid EncryptedKey.mCipherText")
    if (!Array.isArray(raw.mParameters) || !raw.mParameters.every(item => typeof item === "number"))
        throw new Error("Invalid EncryptedKey.mParameters")
    if (typeof raw.mCipher !== "string")
        throw new Error("Invalid EncryptedKey.mCipher");
    if (typeof raw.mToken !== "string")
        throw new Error("Invalid EncryptedKey.mToken");

    return {
        mCipherText: raw.mCipherText,
        mParameters: raw.mParameters,
        mCipher: raw.mCipher,
        mToken: raw.mToken,
    }
}

function validateToken(raw: unknown, json=true): Token {
    if (json) {
        if (typeof raw !== "string")
            throw new Error("Invalid serialized Token");
        try {
            raw = JSON.parse(raw)
        } catch (e) {
            throw new Error("Serialized Token is not valid JSON: " + e);
        }
    }

    if (typeof raw !== "object" || raw === null
        || !("type" in raw)
        || !("label" in raw)
    ) {
        throw new Error("Invalid Token structure");
    }

    if (raw.type !== "TOTP" && raw.type !== "HOTP")
        throw new Error("Invalid Token.type");
    if (typeof raw.label !== "string")
        throw new Error("Invalid Token.label");
    const result: Token = {type: raw.type, label: raw.label};

    if ("issuerExt" in raw) {
        if (typeof raw.issuerExt !== "string")
            throw new Error("Invalid Token.issuerExt");
        result.issuerExt = raw.issuerExt;
    }
    if ("issuerInt" in raw) {
        if (typeof raw.issuerInt !== "string")
            throw new Error("Invalid Token.issuerInt");
        result.issuerInt = raw.issuerInt;
    }
    if ("issuerAlt" in raw) {
        if (typeof raw.issuerAlt !== "string")
            throw new Error("Invalid Token.issuerAlt");
        result.issuerAlt = raw.issuerAlt;
    }
    if ("labelAlt" in raw) {
        if (typeof raw.labelAlt !== "string")
            throw new Error("Invalid Token.labelAlt");
        result.labelAlt = raw.labelAlt;
    }
    if ("algo" in raw) {
        if (raw.algo !== "SHA1" && raw.algo !== "SHA256" && raw.algo !== "SHA512")
            throw new Error("Invalid Token.algo");
        result.algo = raw.algo;
    }
    if ("counter" in raw) {
        if (typeof raw.counter !== "number")
            throw new Error("Invalid Token.counter");
        result.counter = raw.counter;
    }
    if ("period" in raw) {
        if (typeof raw.period !== "number")
            throw new Error("Invalid Token.period");
        result.period = raw.period;
    }
    if ("digits" in raw) {
        if (typeof raw.digits !== "number")
            throw new Error("Invalid Token.digits");
        result.digits = raw.digits;
    }
    if ("lock" in raw) {
        if (typeof raw.lock !== "boolean")
            throw new Error("Invalid Token.lock");
        result.lock = raw.lock;
    }
    if ("image" in raw) {
        if (typeof raw.image !== "string")
            throw new Error("Invalid Token.image");
        result.image = raw.image;
    }
    if ("color" in raw) {
        if (typeof raw.color !== "string")
            throw new Error("Invalid Token.color");
        result.color = raw.color;
    }

    return result;
}


export async function decryptMasterKey(masterKey: MasterKey, password: string): Promise<CryptoKey> {
    let kdf, hmac;
    if (masterKey.mAlgorithm === "PBKDF2withHmacSHA512") {
        kdf = "PBKDF2";
        hmac = "SHA-512";
    } else if (masterKey.mAlgorithm === "PBKDF2withHmacSHA1") {
        kdf = "PBKDF2";
        hmac = "SHA-1";
    } else {
        throw Error("Unexpected MasterKey algorithm: " + masterKey.mAlgorithm);
    }

    const salt = new Uint8Array(masterKey.mSalt);
    const iterations = masterKey.mIterations;

    const kdfParams = {
        name: kdf,
        hash: hmac,
        salt: salt,
        iterations: iterations
    }

    const baseKey = await crypto.subtle.importKey(
        "raw",
        new TextEncoder().encode(password),
        kdfParams.name,
        false,
        ["deriveKey"],
    )

    const decryptionKey = await crypto.subtle.deriveKey(
        kdfParams,
        baseKey,
        {
            name: "AES-GCM",  // EncryptedKey always uses AES-GCM
            length: salt.length * 8,
        },
        false,
        ["decrypt"],
    )

    const {iv, tagLength} = parseDerAesGcmParams(new Uint8Array(masterKey.mEncryptedKey.mParameters))

    const rawDecryptedMasterKey = await crypto.subtle.decrypt(
        {
            name: "AES-GCM",
            iv: new Uint8Array(iv),
            tagLength: tagLength,
            additionalData: new TextEncoder().encode(masterKey.mEncryptedKey.mToken),
        },
        decryptionKey,
        new Uint8Array(masterKey.mEncryptedKey.mCipherText),
    )

    const decryptedMasterKey = await crypto.subtle.importKey(
        "raw",
        rawDecryptedMasterKey,
        "AES-GCM",
        false,
        ["decrypt"],
    )

    return decryptedMasterKey;
}


function parseDerAesGcmParams(params: Uint8Array): {iv: Uint8Array, tagLength: number} {
    const SEQUENCE = 0x30;
    const OCTETSTRING = 0x04;
    const INTEGER = 0x02;

    if (params[0] !== SEQUENCE ||
        params[1] !== params.length-2
    ) {
        throw new Error("Malformed AES/GCM params");
    }

    if (params[2] !== OCTETSTRING)
        throw new Error("Malformed AES/GCM params");

    const stringOffset = 2;
    const stringLength = params[3];

    const intOffset = 4 + stringLength;
    if (params[intOffset] !== INTEGER)
        throw new Error("Malformed AES/GCM params");

    const intLength = params[intOffset + 1];

    if (intLength !== 1 ||
        intOffset + intLength + 2 !== params.length
    ) {
        throw new Error("Malformed AES/GCM params");
    }

    return {
        iv: params.slice(stringOffset+2, stringOffset+2 + stringLength),
        tagLength: params[intOffset + 2] * 8,
    }
}


export async function decryptTokenSecret(masterKey: CryptoKey, encryptedToken: EncryptedKey): Promise<string> {
    const {iv, tagLength} = parseDerAesGcmParams(new Uint8Array(encryptedToken.mParameters))

    const decrypted = await crypto.subtle.decrypt(
        {
            name: "AES-GCM",
            iv: new Uint8Array(iv),
            tagLength: tagLength,
            additionalData: new TextEncoder().encode(encryptedToken.mToken),
        },
        masterKey,
        new Uint8Array(encryptedToken.mCipherText),
    )

    return uint8ToBase32(new Uint8Array(decrypted));
}

function uint8ToBase32(bytes: Uint8Array): string {
    const BASE32_ALPHABET = "ABCDEFGHIJKLMNOPQRSTUVWXYZ234567";
    let bits = 0;
    let value = 0;
    let output = "";

    for (const byte of bytes) {
        value = (value << 8) | byte;
        bits += 8;
        while (bits >= 5) {
            output += BASE32_ALPHABET[(value >>> (bits - 5)) & 31];
            bits -= 5;
        }
    }

    if (bits > 0) {
        output += BASE32_ALPHABET[(value << (5 - bits)) & 31];
    }

    while (output.length % 8 !== 0) {
        output += "=";
    }

    return output;
}


export function tokenToUri(token: Token, secret: string): string {
    const url = new URL("otpauth://example.com/path");

    url.host = token.type.toLowerCase();
    if (token.issuerExt === undefined) {
        url.pathname = token.label;
    } else {
        url.pathname = token.issuerExt + ":" + token.label;
    }

    const params = url.searchParams;

    params.set("secret", secret);

    if (token.issuerInt !== undefined) {
        params.set("issuer", token.issuerInt);
    }
    if (token.issuerAlt !== undefined) {
        params.set("issuerAlt", token.issuerAlt);
    }
    if (token.labelAlt !== undefined) {
        params.set("mLabelAlt", token.labelAlt);
    }
    if (token.algo !== undefined) {
        params.set("algorithm", token.algo);
    }
    if (token.period !== undefined) {
        params.set("period", token.period.toString());
    }
    if (token.digits !== undefined) {
        params.set("digits", token.digits.toString());
    }
    if (token.lock !== undefined) {
        params.set("lock", token.lock.toString());
    }
    if (token.color !== undefined) {
        params.set("color", token.color);
    }
    if (token.image !== undefined) {
        params.set("image", token.image);
    }
    if (token.type === "HOTP") {
        if (token.counter === undefined) {
            throw new Error("HOTP token must have a counter field");
        }
        params.set("counter", token.counter.toString());
    }

    return url.toString();
}


export async function exportFreeOTPBackup(data: Uint8Array, password: string): Promise<string[]> {
    const parsed = parseBackupFile(data);
    const masterKey = await decryptMasterKey(parsed.masterKey, password);

    const result: string[] = [];
    for (const {token, key} of parsed.tokens) {
        const secret = await decryptTokenSecret(masterKey, key);
        const uri = tokenToUri(token, secret);
        result.push(uri);
    }

    return result;
}

export default exportFreeOTPBackup;