const Evilscan = require('evilscan');

const mongoose = require('mongoose');
mongoose.connect('mongodb://localhost:27017/portScan', {useNewUrlParser: true, useUnifiedTopology: true});

const ipSchema = new mongoose.Schema({
    ip: String,
    port: Number,
    banner: String,
    status: String
});
const mongoIP = mongoose.model('scans', ipSchema)

const networkPartSchema = new mongoose.Schema({
    0: Number,
    1: Number,
    date: Date,
})
const networkSearched = mongoose.model('networkParts', networkPartSchema)

// Target: 1-255 . 1-255 . 0 . 0 / 16
// Network Part . Host Part

// Scan through entirety of each network part
// 65025 results per network part

// 1 - 255, 1 - 255
var networkPart = [];
for (let i = 1; i <= 255; i++) {
    for (let j = 1; j <= 255; j++) {
        networkPart.push([i, j]);
    }
}

async function nextScan() {
    randomSelection = networkPart[Math.floor(Math.random() * networkPart.length)]

    // Skip already searched
    // var doc = await networkSearched.find({0: randomSelection[0], 1: randomSelection[1]})
    // if (!doc) {
    //     nextScan();
    //     return;
    // }

    var ip = `${randomSelection.join(".")}.0.0/16`;
    console.log(ip)

    var scan = new Evilscan({
        target: ip,
        port:'25565',
        status:'TROU', // Timeout, Refused, Open, Unreachable
        banner: true,
        timeout: 4000
    })

    scan.on('result', data => {
        console.log(data);
        mongoIP.create(data)
    });
    
    scan.on('error', err => {
        throw new Error(data.toString());
    });
    
    scan.on('done', () => {
        console.log(`Complete scan of network part ${randomSelection}`)
        networkSearched.create({
            0: randomSelection[0],
            1: randomSelection[1],
            date: Date.now(),
        })
        nextScan();    
    });

    scan.run();
    networkPart.splice(networkPart.indexOf(randomSelection), 1)
}

nextScan();