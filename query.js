// Get server information from entries that have port 25565 open'
// https://wiki.vg/Server_List_Ping#Status_Request

const net = require('net');
const varint = require('varint');

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
    console.log("Handshake packet", IDPacket);
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

var connection = net.connect(port, testIP, () => {
    // Handshake
    connection.write(createHandshake(testIP, port));

    // Ping
    connection.write(createPacketWithID(0, Buffer.alloc(0)))

    // Server information should be recieved
});

connection.on('data', (data) => {
    // Decode data - https://wiki.vg/Server_List_Ping#Status_Request
    // Packet ID    Name	        Field Type	    Notes
    // 0x00         JSON Response	String	        See below; as with all strings this 
    //                                              is prefixed by its length as a VarInt(2-byte max)

    console.log('data', data)

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
})

connection.on('close', () => {
    console.log('conn closed')
})