// coverage/core/coverage_utils.js

const crypto = require('crypto');

function makeSignatureFromCoverage(coverageData, options = {}) {
    const { filter } = options;
    const signatureParts = [];

    for (const script of coverageData) {
        const url = script.url;
        if (filter && !filter(url)) continue;
        for (const func of script.functions) {
            for (const range of func.ranges) {
                signatureParts.push(`${url}|${range.startOffset}:${range.endOffset}:${range.count}`);
            }
        }
    }

    signatureParts.sort();
    const signatureStr = signatureParts.join(';');
    const hash = crypto.createHash('sha1').update(signatureStr).digest('hex');
    return { hash, signature: signatureStr };
}

class SignatureManager {
    constructor() {
        this.seenSignatures = new Set();
    }

    checkNewCoverage(coverageData, options = {}) {
        const { hash } = makeSignatureFromCoverage(coverageData, options);
        if (!this.seenSignatures.has(hash)) {
            this.seenSignatures.add(hash);
            return true;
        }
        return false;
    }
}

module.exports = { makeSignatureFromCoverage, SignatureManager };
