// Scan for IPs that have port 25565 open

const Evilscan = require('evilscan');
require('dotenv').config()

const mongoose = require('mongoose');
var mongoConn = process.env.DBPASS ? `mongodb://${process.env.DBUSER}:${process.env.DBPASS}@${process.env.DB}:${process.env.DBPORT}/scanner?authSource=admin` : `mongodb://localhost:27017`;
mongoose.connect(mongoConn, {useNewUrlParser: true, useUnifiedTopology: true});


const ipSchema = require('./schemas').ipSchema;
const mongoIP = mongoose.model('scans', ipSchema)

const networkPartSchema = require('./schemas').networkPartSchema;
const networkSearched = mongoose.model('networkParts', networkPartSchema)

// Target: 1-255 . 1-255 . 0 . 0 / 16
// Network Part . Host Part

// Scan through entirety of each network part
// 65025 results per network part

const saveAll = false;

// 1 - 255, 1 - 255
var networkPart = [];
for (let i = 1; i <= 255; i++) {
    for (let j = 1; j <= 255; j++) {
        if (i <= 10 || (i == 192 && j == 168) || (i == 172)) {
            continue;
        }
        networkPart.push([i, j]);
    }
}

async function nextScan() {
    randomSelection = networkPart[Math.floor(Math.random() * networkPart.length)]

    // Skip already searched
    var doc = await networkSearched.find({0: randomSelection[0], 1: randomSelection[1]})
    if (doc.length > 0) {
        nextScan();
        return;
    }

    var ip = `${randomSelection.join(".")}.0.0/16`;
    console.log(`Starting scan of ${ip}`)

    var scan = new Evilscan({
        target: ip,
        port:'25565',
        status:'TROU', // Timeout, Refused, Open, Unreachable
        banner: true,
        timeout: 4000
    })

    scan.on('result', data => {
        progressBar(data.ip);
        data.lastScan = null;
        if (saveAll || data.status == "open") {
            mongoIP.create(data)
        }
    });
    
    scan.on('error', err => {
        throw new Error(data.toString());
    });
    
    scan.on('done', () => {
        process.stdout.clearLine(0);
        console.log(`Completed scan\n`)
        networkSearched.create({
            0: randomSelection[0],
            1: randomSelection[1],
            date: Date.now(),
        })
        nextScan();    
    });

    scan.run();
    networkPart.splice(networkPart.indexOf(randomSelection), 1);
}

nextScan();


function progressBar(latest) {
    process.stdout.cursorTo(0);
    progress = latest.split(".");

    max = 255;
    intervals = 50;
    tracking = progress[2];

    completed = Math.floor(tracking/(max/intervals));
    notCompleted = intervals - completed;
    percentage = ((tracking/(max))*100).toFixed(2);
    process.stdout.write(`${"█".repeat(completed)}${"▒".repeat(notCompleted)}\t${percentage}%\t${latest}\r`);
}