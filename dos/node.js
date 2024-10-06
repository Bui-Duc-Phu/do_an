const http = require('http');

const options = {
    hostname: '192.168.0.109',
    port: 3000,
    path: '/nonexistentpath', // Đường dẫn không tồn tại để trả về lỗi 404
    method: 'GET'
};

const sendRequest = () => {
    const req = http.request(options, res => {
        console.log(`STATUS: ${res.statusCode}`);
        res.on('data', d => {
            process.stdout.write(d);
        });
    });

    req.on('error', e => {
        console.error(`problem with request: ${e.message}`);
    });

    req.end();
};

const numberOfRequests = 100000; // Số lượng yêu cầu bạn muốn gửi
for (let i = 0; i < numberOfRequests; i++) {
    sendRequest();
}
