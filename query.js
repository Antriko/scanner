// Get server information from entries that have port 25565 open'
// https://wiki.vg/Server_List_Ping#Status_Request

const net = require('net');
const varint = require('varint');

var EventEmitter = require('events');

require('dotenv').config()
const mongoose = require('mongoose');
var mongoConn = process.env.DBPASS ? `mongodb://${process.env.DBUSER}:${process.env.DBPASS}@${process.env.DB}:${process.env.DBPORT}/scanner?authSource=admin` : `mongodb://localhost:27017`;
mongoose.connect(mongoConn, {useNewUrlParser: true, useUnifiedTopology: true});

var testIP = "92.23.213.127";
var port = 25565;

// Handshake needed
// Protocol Version     VarInt - https://wiki.vg/Protocol_version_numbers
// Server Address       String
// Server Port          Unsigned Int
// Next State           VarInt - 1 for status

// Send handshake packet
// Then immediately after send Status Request packet
// Which is a empty packet to confirm connection I assume
// Recieve Status Response and decode then enter into database

function createHandshake(address, port) {
    let protocolBuffer = Buffer.from(varint.encode(760)); // 1.19.1

    let addressBuffer = Buffer.concat([
        Buffer.from(varint.encode(address.length)), 
        Buffer.from(address)
    ])

    // Incase port is Int8, alloc 2 bytes always
    let portBuffer = Buffer.allocUnsafe(2);
    portBuffer.writeInt16BE(port, 0);

    let nextStateBuffer = Buffer.from(varint.encode(1));

    // console.log(protocolBuffer, addressBuffer, portBuffer, nextStateBuffer)
    var packet = Buffer.concat([protocolBuffer, addressBuffer, portBuffer, nextStateBuffer])
    var IDPacket = createPacketWithID(0, packet);
    // console.log("Handshake packet", IDPacket);
    return IDPacket
}

function createPacketWithID(ID, data) {
    // Packet Format - https://wiki.vg/Protocol
    // Field Name	    Field Type	    Notes
    // Length	        VarInt	        Length of Packet ID + Data
    // Packet ID        VarInt	
    // Data	            Byte Array	    Depends on the connection state and packet ID, see the sections below
    
    length = varint.encodingLength(ID) + data.length;

    return Buffer.concat([
        Buffer.from(varint.encode(length)),
        Buffer.from(varint.encode(ID)),
        data
    ])
}

const ipSchema = require('./schemas').ipSchema;
const mongoIP = mongoose.model('scans', ipSchema);

const serverQuerySchema = require('./schemas').serverQuery;
const serverQuery = mongoose.model('query', serverQuerySchema);



async function randomScan() {
    var randomSelection = await mongoIP.findOneAndUpdate({status: "open", lastScan: null}, {lastScan: Date.now()});
    // var randomSelection = await mongoIP.findOne({ip: testIP}); // Test case
    if (!randomSelection) {
        console.log("Finished")
        return;
    }
    queryScan(randomSelection.ip, randomSelection.port, randomScan)
}

async function rescan() {
    var date = Date.now();
    var minutes = 30;    // How old of records to update
    var newDate = new Date(date - minutes * (60 * 1000))
    var server = await serverQuery.findOneAndUpdate({successful:true, date:{$lt: newDate}}, {date: Date.now()});
    if (!server) {
        console.log("Finished")
        return;
    }
    queryScan(server.ip, server.port, rescan)
}


function queryScan(serverIP, serverPort, recursionFunc) {
    var scan = new EventEmitter();
    console.log(`Scanning ${serverIP}`);
    var connection = net.connect(serverPort ? serverPort : port, serverIP, () => {
        // Handshake
        connection.write(createHandshake(serverIP, serverPort));
    
        // Ping
        connection.write(createPacketWithID(0, Buffer.alloc(0)))
        // Server information should be recieved

        // Wait timeout and if nothing is recieved, then just move on to next
        setTimeout(() => {
            scan.emit('timeout')
            connection.end();
        }, 4000);   // 4 seconds
    });

    connection.on('data', async (data) => {
        // Decode data - https://wiki.vg/Server_List_Ping#Status_Request
        // Packet ID    Name	        Field Type	    Notes
        // 0x00         JSON Response	String	        See below; as with all strings this 
        //                                              is prefixed by its length as a VarInt(2-byte max)
    
        // console.log('data', data)

        try {
            var packetLength = varint.decode(data);
            var data = data.subarray(varint.encodingLength(packetLength))
            console.log("PacketLength", packetLength)
    
            var packetID = varint.decode(data)
            var data = data.subarray(varint.encodingLength(packetID))
            console.log("PacketID", packetID)
            
            var fieldName = varint.decode(data);
            var data = data.subarray(varint.encodingLength(fieldName))
            console.log("FieldName", fieldName)
            
            // Get actual server data
            var data = JSON.parse(data);

            scan.emit('success', data)
        } catch(e) {
            // console.log(serverIP, e);
            scan.emit('error');
        }
    })

    connection.on('error', (err) => {
        scan.emit('error');
    })

    scan.on('success', async (data) => {
        console.log(`Success SCAN\t${serverIP}`)

        var didUpdate = await serverQuery.findOneAndUpdate({ip: serverIP}, {
            data: data
        })
        scan.emit('nextScan');
        if (didUpdate) return;

        await serverQuery.create({
            ip: serverIP,
            successful: true,
            data: data,
            date: Date.now()
        })
    })

    scan.on('error', async () => {
        console.log(`Error SCAN\t${serverIP}`)
        await serverQuery.create({
            ip: serverIP,
            successful: false,
            date: Date.now()
        })
        scan.emit('nextScan');
    })

    scan.on('timeout', async () => {
        console.log(`Timeout SCAN\t${serverIP}`)
        await serverQuery.create({
            ip: serverIP,
            successful: false,
            date: Date.now()
        })
        scan.emit('nextScan');
    })

    scan.once('nextScan', () => {
        recursionFunc();
    })
}


const inquirer = require('inquirer');

function prompt() {
    var prompt1 = 'What type of scan?'
    var prompt2 = 'How many active scans? Limit 100'

    inquirer.prompt([
        {
            type: 'list',
            name: prompt1,
            choices: [
                'Rescan',
                'New scans'
            ]
        },
        {
            type: 'number',
            name: prompt2,
        }
    ])
    .then(ans => {
        if (ans[prompt2] == NaN) {
            console.log('Please enter a number')
            prompt();
            return;
        }
        if (ans[prompt2] > 100) {
            ans[prompt2] = 100;
        }
        for (let i = 0; i < ans[prompt2]; i++) {
            switch (ans[prompt1]) {
                case 'Rescan':
                    rescan()
                    break;
                    case 'New scans':
                    randomScan()
                    break;
                }
            }
        })
}
prompt();