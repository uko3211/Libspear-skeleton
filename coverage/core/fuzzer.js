const fs = require('fs');
const path = require('path');
const inspector = require('inspector');
const { spawnSync } = require('child_process');
const { SignatureManager } = require('./coverage_utils');

class FuzzingStats {
    constructor() {
        this.startTime = Date.now();
        this.totalExecs = 0;
        this.crashCount = 0;
        this.uniqueCrashes = new Set();
        this.paths = 0;
        this.currentCoverage = 0;
        this.cumulativeCoverage = 0;
        this.maxCoverage = 0;
        this.execsPerSec = 0;
        this.lastExecTime = Date.now();
        this.execTimes = [];
        this.lastInput = '';
        this.currentStage = 'initializing';
    }

    updateExec(input, currentCoverage, cumulativeCoverage, isCrash = false, isNewPath = false) {
        this.totalExecs++;
        this.lastInput = input;
        this.currentCoverage = typeof currentCoverage === 'number' ? currentCoverage : 0;
        this.cumulativeCoverage = typeof cumulativeCoverage === 'number' ? cumulativeCoverage : 0;
        if (this.currentCoverage > this.maxCoverage) this.maxCoverage = this.currentCoverage;
        if (isCrash) {
            this.crashCount++;
            this.uniqueCrashes.add(input);
        }
        if (isNewPath) this.paths++;
        const now = Date.now();
        this.execTimes.push(now);
        while (this.execTimes.length && now - this.execTimes[0] > 10000) this.execTimes.shift();
        this.execsPerSec = this.execTimes.length / 10;
        this.lastExecTime = now;
    }

    getRuntime() {
        const elapsed = Date.now() - this.startTime;
        const hours = Math.floor(elapsed / 3600000);
        const minutes = Math.floor((elapsed % 3600000) / 60000);
        const seconds = Math.floor((elapsed % 60000) / 1000);
        return `${String(hours).padStart(2,'0')}:${String(minutes).padStart(2,'0')}:${String(seconds).padStart(2,'0')}`;
    }

    toJSON() {
        return {
            runtime: this.getRuntime(),
            totalExecs: this.totalExecs,
            crashCount: this.crashCount,
            uniqueCrashes: this.uniqueCrashes.size,
            paths: this.paths,
            currentCoverage: this.currentCoverage,
            cumulativeCoverage: this.cumulativeCoverage,
            maxCoverage: this.maxCoverage,
            execsPerSec: this.execsPerSec,
            lastInputPreview: this.lastInput ? (this.lastInput.length > 200 ? this.lastInput.slice(0,200) + '...' : this.lastInput) : ''
        };
    }
}

class FuzzerCore {
    constructor(options = {}) {
        this.stats = new FuzzingStats();
        this.targetModule = null;
        this.session = null;
        this.sigMgr = new SignatureManager();
        this.corpusDir = options.corpusDir || path.resolve(__dirname, '../corpus');
        this.seedInputs = [];
        this.mutatorPyPath = '';
        this.isRunning = false;
        this.targetFilePath = '';
        this.allRanges = new Set();
        this.executedRanges = new Set();
        this.takeCoverageLock = false;
        this.pendingCoveragePromises = [];
        this.mutatorMaxBuffer = options.mutatorMaxBuffer || 10 * 1024 * 1024;
        this.mutatorTimeoutMs = options.mutatorTimeoutMs || 5000;
        this.execDelayMs = typeof options.execDelayMs === 'number' ? options.execDelayMs : 10;
        this.saveCrashes = typeof options.saveCrashes === 'boolean' ? options.saveCrashes : true;
        if (!fs.existsSync(this.corpusDir)) fs.mkdirSync(this.corpusDir, { recursive: true });
    }

    async init(targetJSPath, mutatorPyPath, seedFilePath) {
        this.targetFilePath = path.resolve(targetJSPath);
        delete require.cache[require.resolve(this.targetFilePath)];
        if (typeof global.db === 'undefined') {
            global.db = {
                all(query, params, cb) {
                    if (typeof params === 'function') {
                        cb = params;
                        params = [];
                    }
                    if (typeof cb === 'function') {
                        cb(null, []);
                    }
                }
            };
        }
        this.targetModule = require(this.targetFilePath);
        this.mutatorPyPath = mutatorPyPath || '';
        this.session = new inspector.Session();
        this.session.connect();
        await this._post('Profiler.enable');
        await this._post('Profiler.startPreciseCoverage', { detailed: true, callCount: true, allowSampled: false });
        if (seedFilePath && fs.existsSync(seedFilePath)) {
            const seedRaw = fs.readFileSync(seedFilePath, 'utf-8');
            const seeds = seedRaw.split(/\r?\n/).map(s => s.trim()).filter(Boolean);
            if (seeds.length) this.seedInputs.push(...seeds);
            else this.seedInputs.push('initial');
        } else {
            this.seedInputs.push('initial');
        }
        this.stats.currentStage = 'ready';
    }

    _post(method, params = {}) {
        return new Promise((resolve, reject) => {
            try {
                this.session.post(method, params, (err, res) => {
                    if (err) return reject(err);
                    resolve(res);
                });
            } catch (e) {
                reject(e);
            }
        });
    }

    _safeMutate(input) {
        if (!this.mutatorPyPath) return input;
        try {
            const res = spawnSync('python', [this.mutatorPyPath], {
                input: input,
                encoding: 'utf-8',
                maxBuffer: this.mutatorMaxBuffer,
                timeout: this.mutatorTimeoutMs
            });
            if (res.error) return input;
            return (res.stdout || '').toString().trim() || input;
        } catch (e) {
            return input;
        }
    }

    // 공개 래퍼 (UI에서 사용)
    mutateInput(input) {
        return this._safeMutate(String(input));
    }

    async _takePreciseCoverage() {
        if (!this.session) return { result: [] };

        while (this.takeCoverageLock) {
            await new Promise(r => setTimeout(r, 5));
        }
        this.takeCoverageLock = true;
        try {
            return await this._post('Profiler.takePreciseCoverage');
        } finally {
            this.takeCoverageLock = false;
        }
    }

    _extractCoverage(result) {
        const scripts = result && result.result ? result.result : (result || []);
        let snapshotTotalRanges = 0;
        let snapshotExecutedRanges = 0;
        for (const script of scripts) {
            const url = script.url || (`<anon:${script.scriptId}>`);
            if (!this._isTargetUrl(url)) continue;
            const funcs = script.functions || [];
            for (const func of funcs) {
                const ranges = func.ranges || [];
                for (const r of ranges) {
                    const rangeKey = `${url}:${r.startOffset}:${r.endOffset}`;
                    this.allRanges.add(rangeKey);
                    snapshotTotalRanges++;
                    if (r.count && r.count > 0) {
                        this.executedRanges.add(rangeKey);
                        snapshotExecutedRanges++;
                    }
                }
            }
        }
        const totalRangesSeen = this.allRanges.size;
        const currentCoveragePercent = snapshotTotalRanges > 0 ? (snapshotExecutedRanges / snapshotTotalRanges) * 100 : 0;
        const cumulativeCoveragePercent = totalRangesSeen > 0 ? (this.executedRanges.size / totalRangesSeen) * 100 : 0;
        return {
            coverage: currentCoveragePercent,
            cumulativeCoverage: cumulativeCoveragePercent,
            totalRanges: snapshotTotalRanges,
            executedRanges: snapshotExecutedRanges,
            cumulativeRanges: this.executedRanges.size,
            allRangesCount: totalRangesSeen
        };
    }

    _isTargetUrl(url) {
        try {
            // 파일 URL, 절대경로, 혹은 파일명 포함 여부로 판단
            const fileUrl = url.replace('file://', '');
            if (fileUrl === this.targetFilePath) return true;
            if (fileUrl.endsWith(path.basename(this.targetFilePath))) return true;
            if (url.includes(this.targetFilePath)) return true;
            return false;
        } catch (e) {
            return url.includes(path.basename(this.targetFilePath));
        }
    }

    async runInput(input, timeoutMs = 2000) {
        const exportedFuncs = Object.keys(this.targetModule).filter(k => typeof this.targetModule[k] === 'function');
        let crashed = false;
        let crashInfo = null;
        for (const funcName of exportedFuncs) {
            try {
                const targetFn = this.targetModule[funcName];
                const paramNames = this._extractParamNames(targetFn);
                const expectedArgs = Math.max(1, paramNames.length || (typeof targetFn.length === 'number' ? targetFn.length : 0));
                const preparedArgs = this._prepareArguments(input, expectedArgs, paramNames);
                const coercedArgs = this._coerceArguments(funcName, preparedArgs, expectedArgs, paramNames);

                const res = targetFn(...coercedArgs);
                if (res && typeof res.then === 'function') {
                    await Promise.race([res, new Promise((_, rej) => setTimeout(() => rej(new Error('function timeout')), timeoutMs))]).catch(e => { throw e; });
                }
            } catch (e) {
                crashed = true;
                crashInfo = { func: funcName, message: e && e.message ? e.message : String(e), stack: e && e.stack ? e.stack : '' };
                if (this.saveCrashes) {
                    try {
                        const fname = `crash_${Date.now()}_${process.hrtime.bigint().toString()}_${funcName}.json`;
                        const fpath = path.join(this.corpusDir, fname);
                        fs.writeFileSync(fpath, JSON.stringify({ input, crashInfo }, null, 2), { encoding: 'utf-8' });
                    } catch (we) {}
                }
            }
        }
        const covResult = await this._takePreciseCoverage();
        const cov = this._extractCoverage(covResult);
        return Object.assign({ crashed, crashInfo, coverageData: covResult }, cov);
    }

    _prepareArguments(rawInput, expectedArgs, paramNames = []) {
        const args = [];
        const input = rawInput ?? '';

        if (expectedArgs <= 1) {
            return [this._coerceToken(input, paramNames[0])];
        }

        if (typeof input === 'string') {
            const trimmed = input.trim();
            let parsed = null;
            if ((trimmed.startsWith('[') && trimmed.endsWith(']')) || (trimmed.startsWith('{') && trimmed.endsWith('}'))) {
                try {
                    parsed = JSON.parse(trimmed);
                } catch (e) {
                    parsed = null;
                }
            }

            if (Array.isArray(parsed)) {
                args.push(...parsed);
            } else if (parsed && typeof parsed === 'object') {
                args.push(...Object.values(parsed));
            }

            if (!args.length) {
                const splitByNewline = trimmed.split(/\r?\n/).filter(Boolean);
                if (splitByNewline.length >= expectedArgs) {
                    args.push(...splitByNewline.slice(0, expectedArgs));
                } else {
                    const splitByDelimiter = trimmed.split(/\s*(?:\|\||\||::)\s*/).filter(Boolean);
                    if (splitByDelimiter.length >= expectedArgs) {
                        args.push(...splitByDelimiter.slice(0, expectedArgs));
                    }
                }
            }
        }

        while (args.length < expectedArgs) {
            args.push(input);
        }

        const limited = args.slice(0, expectedArgs);
        return limited.map((value, idx) => this._coerceToken(value, paramNames[idx]));
    }

    _coerceArguments(funcName, preparedArgs, expectedArgs, paramNames = []) {
        const normalized = Array.isArray(preparedArgs)
            ? preparedArgs.slice(0, expectedArgs)
            : [preparedArgs];

        while (normalized.length < expectedArgs) {
            normalized.push('');
        }

        for (let i = 0; i < expectedArgs; i++) {
            const name = paramNames[i] || '';
            if (this._isArrayParam(name)) {
                if (!Array.isArray(normalized[i])) {
                    if (typeof normalized[i] === 'string') {
                        const parts = normalized[i].split(',').map(v => v.trim()).filter(Boolean);
                        if (parts.length > 1) {
                            normalized[i] = parts;
                        } else {
                            const whites = normalized[i].split(/\s+/).filter(Boolean);
                            normalized[i] = whites.length ? whites : [normalized[i]];
                        }
                    } else if (normalized[i] === undefined || normalized[i] === null) {
                        normalized[i] = [];
                    } else {
                        normalized[i] = [normalized[i]];
                    }
                }
            } else if (Array.isArray(normalized[i])) {
                normalized[i] = normalized[i][0] ?? '';
            }
        }

        return normalized;
    }

    _coerceToken(value, paramName = '') {
        if (value === undefined || value === null) return value;
        if (typeof value !== 'string') return value;
        const trimmed = value.trim();
        if (!trimmed.length) return trimmed;
        if (this._isArrayParam(paramName)) {
            if (trimmed.startsWith('[') && trimmed.endsWith(']')) {
                try {
                    const parsed = JSON.parse(trimmed);
                    if (Array.isArray(parsed)) return parsed;
                } catch (e) {}
            }
            if (trimmed.includes(',')) {
                return trimmed.split(',').map(v => v.trim()).filter(Boolean);
            }
            return trimmed.split(/\s+/).filter(Boolean);
        }
        return trimmed;
    }

    _extractParamNames(targetFn) {
        if (typeof targetFn !== 'function') return [];
        const src = targetFn.toString().replace(/\s+/g, ' ');
        const patterns = [
            /^function\s*[^(]*\(([^)]*)\)/,
            /^\(([^)]*)\)\s*=>/,
            /^[^(]*\(([^)]*)\)\s*\{/
        ];
        for (const pattern of patterns) {
            const match = src.match(pattern);
            if (match && match[1] !== undefined) {
                return match[1]
                    .split(',')
                    .map(p => p.trim())
                    .filter(Boolean)
                    .map(p => p.split('=')[0].trim().replace(/\/\*.*?\*\//g, ''));
            }
        }
        return [];
    }

    _isArrayParam(name) {
        if (!name) return false;
        return /(args?|list|array|items|values|options|commands|parameters)/i.test(name);
    }

    async startFuzzing(maxIterations = 1000, updateCallback = () => {}) {
        this.isRunning = true;
        this.stats.currentStage = 'fuzzing';
        for (let i = 0; i < maxIterations && this.isRunning; i++) {
            const seed = this.seedInputs[Math.floor(Math.random() * this.seedInputs.length)];
            const testInput = this._safeMutate(seed);
            let result;
            try {
                result = await this.runInput(testInput);
            } catch (e) {
                result = { coverage: 0, cumulativeCoverage: (this.executedRanges.size / Math.max(1, this.allRanges.size)) * 100, crashed: false, coverageData: null };
            }
            let isNewPath = false;
            try {
                const coveragePayload = result.coverageData;
                if (this.sigMgr && typeof this.sigMgr.checkNewCoverage === 'function') {
                    isNewPath = this.sigMgr.checkNewCoverage(coveragePayload, { filter: url => this._isTargetUrl(url) });
                } else {
                    if (result.cumulativeRanges > (this.stats.paths + 0)) isNewPath = true;
                }
            } catch (e) {
                isNewPath = false;
            }
            if (isNewPath) {
                try {
                    const fname = `input_${Date.now()}_${process.hrtime.bigint().toString()}.txt`;
                    fs.writeFileSync(path.join(this.corpusDir, fname), testInput, { encoding: 'utf-8' });
                    this.seedInputs.push(testInput);
                } catch (e) {}
            }
            this.stats.updateExec(testInput, result.coverage, result.cumulativeCoverage, result.crashed, isNewPath);
            try { updateCallback(this.stats.toJSON()); } catch (e) {}
            await new Promise(r => setTimeout(r, this.execDelayMs));
        }
        this.isRunning = false;
        this.stats.currentStage = 'completed';
        try { updateCallback(this.stats.toJSON()); } catch (e) {}
        try {
            await this._post('Profiler.stopPreciseCoverage');
            await this._post('Profiler.disable');
        } catch (e) {}
        try { this.session.disconnect(); } catch (e) {}
    }

    stop() {
        this.isRunning = false;
        this.stats.currentStage = 'stopping';
        try { this._post('Profiler.stopPreciseCoverage').catch(()=>{}); } catch {}
        try { this._post('Profiler.disable').catch(()=>{}); } catch {}
        try { this.session.disconnect(); } catch {}
    }

    addSeed(seed) {
        if (!seed) return;
        this.seedInputs.push(String(seed));
    }

    resetCoverage() {
        this.allRanges = new Set();
        this.executedRanges = new Set();
    }

    exportState(dir) {
        try {
            if (!fs.existsSync(dir)) fs.mkdirSync(dir, { recursive: true });
            const state = {
                stats: this.stats.toJSON(),
                allRanges: Array.from(this.allRanges),
                executedRanges: Array.from(this.executedRanges),
                seeds: this.seedInputs.slice()
            };
            const fname = path.join(dir, `fuzzer_state_${Date.now()}.json`);
            fs.writeFileSync(fname, JSON.stringify(state, null, 2), 'utf-8');
            return fname;
        } catch (e) {
            return null;
        }
    }

    importState(file) {
        try {
            if (!fs.existsSync(file)) return false;
            const raw = fs.readFileSync(file, 'utf-8');
            const st = JSON.parse(raw);
            if (st.seeds && Array.isArray(st.seeds)) this.seedInputs = st.seeds;
            if (st.allRanges && Array.isArray(st.allRanges)) this.allRanges = new Set(st.allRanges);
            if (st.executedRanges && Array.isArray(st.executedRanges)) this.executedRanges = new Set(st.executedRanges);
            return true;
        } catch (e) {
            return false;
        }
    }
}

module.exports = { FuzzerCore, FuzzingStats };
