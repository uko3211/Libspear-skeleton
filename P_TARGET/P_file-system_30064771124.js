const path = require('path');
const fs = require('fs');

function unsafeFileStream(fileName, data) {
    const filePath = path.join('/tmp', fileName);
    const writer = fs.createWriteStream(filePath);
    writer.write(data);
    writer.end();
    console.log(`Streamed to ${filePath}`);
}

module.exports = { unsafeFileStream };