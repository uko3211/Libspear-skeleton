const path = require('path');
const { FuzzerCore } = require('./fuzzer');

class FuzzerUI {
    constructor(fuzzer) {
        this.fuzzer = fuzzer;
        this.isInteractiveMode = false;
        this.inputBuffer = '';
        this.showInputPrompt = false;
    }

    clearScreen() {
        process.stdout.write('\x1b[2J\x1b[0f');
    }

    clearArea(x, y, width) {
        const spaces = ' '.repeat(width);
        process.stdout.write(`\x1b[${y};${x}H${spaces}`);
    }

    drawBox(x, y, width, height, title = '') {
        const horizontal = '─'.repeat(width - 2);
        const topLine = `┌${horizontal}┐`;
        const bottomLine = `└${horizontal}┘`;
        const sideLine = '│' + ' '.repeat(width - 2) + '│';

        process.stdout.write(`\x1b[${y};${x}H${topLine}`);
        
        if (title) {
            const titlePadding = Math.max(0, Math.floor((width - title.length - 2) / 2));
            process.stdout.write(`\x1b[${y};${x + titlePadding + 1}H${title}`);
        }

        for (let i = 1; i < height - 1; i++) {
            process.stdout.write(`\x1b[${y + i};${x}H${sideLine}`);
        }

        process.stdout.write(`\x1b[${y + height - 1};${x}H${bottomLine}`);
    }

    writeAt(x, y, text, color = '') {
        const colorCode = {
            red: '\x1b[31m',
            green: '\x1b[32m',
            yellow: '\x1b[33m',
            blue: '\x1b[34m',
            magenta: '\x1b[35m',
            cyan: '\x1b[36m',
            white: '\x1b[37m',
            bright: '\x1b[1m',
            reset: '\x1b[0m'
        };

        const prefix = color ? (colorCode[color] || '') : '';
        const suffix = color ? colorCode.reset : '';
        process.stdout.write(`\x1b[${y};${x}H${prefix}${text}${suffix}`);
    }

    writeAtAndClear(x, y, text, maxWidth, color = '') {
        const colorCode = {
            red: '\x1b[31m',
            green: '\x1b[32m',
            yellow: '\x1b[33m',
            blue: '\x1b[34m',
            magenta: '\x1b[35m',
            cyan: '\x1b[36m',
            white: '\x1b[37m',
            bright: '\x1b[1m',
            reset: '\x1b[0m'
        };

        const prefix = color ? (colorCode[color] || '') : '';
        const suffix = color ? colorCode.reset : '';
        
        const truncatedText = text.length > maxWidth ? text.substring(0, maxWidth) : text;
        
        const padding = ' '.repeat(Math.max(0, maxWidth - truncatedText.length));
        
        process.stdout.write(`\x1b[${y};${x}H${prefix}${truncatedText}${padding}${suffix}`);
    }

    drawInterface() {
        this.clearScreen();
        
        const width = process.stdout.columns || 80;
        const height = process.stdout.rows || 24;

        this.writeAt(1, 1, '═'.repeat(width), 'cyan');
        const headerTitle = this.isInteractiveMode ? ' Libspear - Interactive Mode ' : ' Libspear - Batch Mode ';
        this.writeAt(Math.floor((width - headerTitle.length) / 2), 1, headerTitle, 'bright');
        
        this.drawBox(2, 3, Math.floor(width * 0.48), 12, ' Fuzzing Statistics ');
        this.drawBox(Math.floor(width * 0.52), 3, Math.floor(width * 0.46), 12, ' Coverage Info ');
        
        if (this.isInteractiveMode) {
            this.drawBox(2, 15, width - 3, 8, ' Interactive Input ');
        } else {
            this.drawBox(2, 15, width - 3, 6, ' Current Input ');
        }
        
        this.writeAt(1, height - 1, '═'.repeat(width), 'cyan');
        
        this.updateDisplay();
    }

    updateDisplay() {
        const stats = this.fuzzer.stats;
        const width = process.stdout.columns || 80;
        const height = process.stdout.rows || 24;
        const leftBoxStart = 4;
        const rightBoxStart = Math.floor(width * 0.52) + 2;
        const inputBoxWidth = width - 7;

        this.writeAt(leftBoxStart, 5, `Runtime        : ${stats.getRuntime()}`);
        this.writeAt(leftBoxStart, 6, `Total execs    : ${stats.totalExecs.toLocaleString()}`, 'green');
        this.writeAt(leftBoxStart, 7, `Exec speed     : ${stats.execsPerSec.toFixed(1)}/sec`, 'yellow');
        this.writeAt(leftBoxStart, 8, `Total paths    : ${stats.paths}`, 'cyan');
        this.writeAt(leftBoxStart, 9, `Unique crashes : ${stats.uniqueCrashes.size}`, 'red');
        this.writeAt(leftBoxStart, 10, `Total crashes  : ${stats.crashCount}`, 'red');
        this.writeAt(leftBoxStart, 11, `Current stage  : ${stats.currentStage}`, 'magenta');
        
        this.writeAt(rightBoxStart, 5, `Current cov    : ${stats.currentCoverage.toFixed(2)}%`);
        this.writeAt(rightBoxStart, 6, `Max coverage   : ${stats.maxCoverage.toFixed(2)}%`, 'green');
        
        const trend = stats.currentCoverage >= stats.maxCoverage * 0.95 ? '↗' : 
                     stats.currentCoverage >= stats.maxCoverage * 0.8 ? '→' : '↘';
        this.writeAt(rightBoxStart, 7, `Trend          : ${trend}`, 'cyan');

        if (this.isInteractiveMode) {
            const userInputText = `Your Input: "${this.inputBuffer}"`;
            this.writeAtAndClear(4, 17, userInputText, inputBoxWidth);
            
            const inputPreview = stats.lastInput.length > inputBoxWidth - 15 ? 
                stats.lastInput.substring(0, inputBoxWidth - 18) + '...' : 
                stats.lastInput;
            const mutatedText = `Last Mutated: "${inputPreview}"`;
            this.writeAtAndClear(4, 18, mutatedText, inputBoxWidth);
            
            const lengthText = `Input Length: ${this.inputBuffer.length} chars`;
            this.writeAtAndClear(4, 19, lengthText, inputBoxWidth);
            
            const mutatedLengthText = `Mutation Length: ${stats.lastInput.length} chars`;
            this.writeAtAndClear(4, 20, mutatedLengthText, inputBoxWidth);
            
            if (this.showInputPrompt) {
                const promptText = '> Type characters (Enter=test, Ctrl+C=exit)';
                this.writeAtAndClear(4, 21, promptText, inputBoxWidth, 'yellow');
            }
        } else {
            const inputPreview = stats.lastInput.length > inputBoxWidth - 10 ? 
                stats.lastInput.substring(0, inputBoxWidth - 13) + '...' : 
                stats.lastInput;
            const inputText = `Input: "${inputPreview}"`;
            this.writeAtAndClear(4, 17, inputText, inputBoxWidth);
            
            const lengthText = `Length: ${stats.lastInput.length} bytes`;
            this.writeAtAndClear(4, 18, lengthText, inputBoxWidth);
        }

        let statusMsg, statusColor;
        if (this.isInteractiveMode) {
            statusMsg = this.fuzzer.isRunning ? 
                ' [INTERACTIVE] Type to fuzz, Ctrl+C to stop ' : 
                ' [STOPPED] Interactive session ended ';
            statusColor = this.fuzzer.isRunning ? 'green' : 'red';
        } else {
            statusMsg = this.fuzzer.isRunning ? 
                ' [RUNNING] Press Ctrl+C to stop ' : 
                ' [STOPPED] Fuzzing completed ';
            statusColor = this.fuzzer.isRunning ? 'green' : 'red';
        }
        
        this.writeAt(2, height - 1, statusMsg, statusColor);
    }

    createProgressBar(current, max, width) {
        const percentage = max > 0 ? current / max : 0;
        const filled = Math.floor(percentage * width);
        const empty = width - filled;
        
        const bar = '█'.repeat(filled) + '░'.repeat(empty);
        return `[${bar}] ${(percentage * 100).toFixed(1)}%`;
    }

    setupInteractiveInput(onExit) {
        this.isInteractiveMode = true;
        this.showInputPrompt = true;
        this.onExit = onExit;
        
        if (process.stdin.setRawMode) {
            process.stdin.setRawMode(true);
        }
        
        process.stdin.resume();
        
        process.stdin.on('data', (data) => {
            const char = data.toString();
            const charCode = data[0];
            
            if (charCode === 3) {
                this.exitInteractiveMode();
                return;
            }
            
            if (charCode === 13 || charCode === 10) {
                if (this.inputBuffer.length > 0) {
                    this.sendInputToFuzzer(this.inputBuffer);
                    this.inputBuffer = '';
                    this.updateDisplay();
                }
                return;
            }
            
            if (charCode === 127 || charCode === 8) {
                if (this.inputBuffer.length > 0) {
                    this.inputBuffer = this.inputBuffer.slice(0, -1);
                    this.updateDisplay();
                }
                return;
            }
            
            if (charCode >= 32 && charCode <= 126) {
                this.inputBuffer += char;
                
                this.sendInputToFuzzer(this.inputBuffer);
                this.updateDisplay();
            }
        });
    }

    exitInteractiveMode() {
        if (process.stdin.setRawMode) {
            process.stdin.setRawMode(false);
        }
        
        process.stdin.removeAllListeners('data');
        process.stdin.pause();
        
        this.fuzzer.stop();
        
        this.clearScreen();
        
        console.log('\nInteractive fuzzing stopped.');
        console.log(`Total executions: ${this.fuzzer.stats.totalExecs}`);
        console.log(`Unique crashes: ${this.fuzzer.stats.uniqueCrashes.size}`);
        console.log(`Max coverage: ${this.fuzzer.stats.maxCoverage.toFixed(2)}%`);
        
        if (this.onExit) {
            this.onExit();
        }
        
        process.exit(0);
    }

    async sendInputToFuzzer(input) {
        try {
            const mutatedInput = this.fuzzer.mutateInput(input);
            
            const result = await this.fuzzer.runInput(mutatedInput);

            let isNewPath = false;
            try {
                if (this.fuzzer.sigMgr && typeof this.fuzzer.sigMgr.checkNewCoverage === 'function') {
                    isNewPath = this.fuzzer.sigMgr.checkNewCoverage(result.coverageData, { filter: url => url.endsWith('.js') });
                } else {
                    isNewPath = result.cumulativeRanges > this.fuzzer.stats.paths;
                }
            } catch (e) {
                isNewPath = false;
            }

            this.fuzzer.stats.updateExec(mutatedInput, result.coverage, result.cumulativeCoverage, result.crashed, isNewPath);
            
            if (isNewPath || result.crashed) {
                const timestamp = Date.now();
                const filename = result.crashed ? 
                    `crash_${timestamp}.txt` : 
                    `input_${timestamp}.txt`;
                
                const fs = require('fs');
                fs.writeFileSync(
                    path.join(this.fuzzer.corpusDir, filename), 
                    mutatedInput
                );
                
                if (isNewPath) {
                    this.fuzzer.seedInputs.push(mutatedInput);
                }
            }
            
        } catch (error) {
            console.error('Error in interactive fuzzing:', error);
        }
    }
}

function printUsage() {
    console.log(`
Usage: node fuzzer_interface.js <target_js> <mutator_py> [options] [seed_file]

Options:
    --batch [iterations]    Batch mode (default: 1000 iterations)
    --interactive          Interactive mode with real-time input
    --help                 Show this help

Examples:
    node fuzzer_interface.js target.js mutator.py --batch 5000
    node fuzzer_interface.js target.js mutator.py --interactive
    node fuzzer_interface.js target.js mutator.py --batch 1000 seed.txt
`);
}

function parseArgs() {
    const args = process.argv.slice(2);
    
    if (args.length < 2 || args.includes('--help')) {
        printUsage();
        process.exit(0);
    }

    const config = {
        targetJs: args[0],
        mutatorPy: args[1],
        mode: 'batch',
        iterations: 1000,
        seedFile: null
    };

    for (let i = 2; i < args.length; i++) {
        const arg = args[i];
        
        if (arg === '--batch') {
            config.mode = 'batch';
            if (i + 1 < args.length && !isNaN(parseInt(args[i + 1]))) {
                config.iterations = parseInt(args[i + 1]);
                i++;
            }
        } else if (arg === '--interactive') {
            config.mode = 'interactive';
        } else if (!arg.startsWith('--')) {
            config.seedFile = arg;
        }
    }

    return config;
}

async function runBatchMode(fuzzer, ui, iterations) {
    ui.drawInterface();
    
    await fuzzer.startFuzzing(iterations, () => {
        ui.updateDisplay();
    });

    setTimeout(() => {
        ui.clearScreen();
        console.log('Fuzzing completed!');
        console.log(`Total executions: ${fuzzer.stats.totalExecs}`);
        console.log(`Unique crashes: ${fuzzer.stats.uniqueCrashes.size}`);
        console.log(`Max coverage: ${fuzzer.stats.maxCoverage.toFixed(2)}%`);
        process.exit(0);
    }, 1000);
}

async function runInteractiveMode(fuzzer, ui) {
    fuzzer.isRunning = true;
    fuzzer.stats.currentStage = 'interactive_ready';

    if (!process.stdin.isTTY) {
        let input = '';
        process.stdin.on('data', (chunk) => {
            input += chunk;
        });
        process.stdin.on('end', async () => {
            await ui.sendInputToFuzzer(input.trim());
            // Fuzzing and analysis is done, now print results and exit.
            console.log('\nFuzzing completed!');
            console.log(`Total executions: ${fuzzer.stats.totalExecs}`);
            console.log(`Unique crashes: ${fuzzer.stats.uniqueCrashes.size}`);
            console.log(`Current cov    : ${fuzzer.stats.currentCoverage.toFixed(2)}%`);
            console.log(`Max coverage   : ${fuzzer.stats.maxCoverage.toFixed(2)}%`);
            process.exit(0);
        });
        return;
    }
    
    let displayInterval;
    let isExiting = false;
    
    const exitHandler = () => {
        if (isExiting) return;
        isExiting = true;
        
        if (displayInterval) {
            clearInterval(displayInterval);
        }
        
        ui.exitInteractiveMode();
    };
    
    ui.setupInteractiveInput(exitHandler);
    ui.drawInterface();
    
    displayInterval = setInterval(() => {
        if (!isExiting) {
            ui.updateDisplay();
        }
    }, 1000);

    process.removeAllListeners('SIGINT');
    process.on('SIGINT', exitHandler);

    return new Promise(() => {});
}

async function main() {
    try {
        const config = parseArgs();
        
        const fs = require('fs');
        if (!fs.existsSync(config.targetJs)) {
            console.error(`Error: Target file not found: ${config.targetJs}`);
            process.exit(1);
        }
        
        if (!fs.existsSync(config.mutatorPy)) {
            console.error(`Error: Mutator file not found: ${config.mutatorPy}`);
            process.exit(1);
        }

        const fuzzer = new FuzzerCore();
        const ui = new FuzzerUI(fuzzer);
        
        await fuzzer.init(
            path.resolve(config.targetJs), 
            config.mutatorPy, 
            config.seedFile
        );

        if (config.mode === 'batch') {
            process.on('SIGINT', () => {
                fuzzer.stop();
                ui.clearScreen();
                console.log('\nFuzzing stopped by user.');
                process.exit(0);
            });
            
            await runBatchMode(fuzzer, ui, config.iterations);
        } else if (config.mode === 'interactive') {
            await runInteractiveMode(fuzzer, ui);
        }

    } catch (error) {
        console.error('Failed to initialize fuzzer:', error);
        process.exit(1);
    }
}

main();
