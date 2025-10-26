const path = require('path');
const fs = require('fs');

function unsafeFileWrite(fileName, data) {
    const filePath = path.join('/tmp', fileName);
    fs.writeFileSync(filePath, data);
    console.log(`Wrote to ${filePath}`);
}

module.exports = {
    unsafeFileWrite
};