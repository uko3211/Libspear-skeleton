const http = require('http');

function unsafeHttpRequest(url) {
    http.get(url, (res) => {
        let data = '';
        res.on('data', (chunk) => {
            data += chunk;
        });
        res.on('end', () => {
            console.log('Response from server:', data);
        });
    }).on('error', (err) => {
        console.error('HTTP request error:', err.message);
    });
}

module.exports = {
    unsafeHttpRequest
};