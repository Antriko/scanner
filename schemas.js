const mongoose = require('mongoose');

const schemas = {}

schemas.networkPartSchema = new mongoose.Schema({
    0: Number,
    1: Number,
    date: Date,
})

schemas.ipSchema = new mongoose.Schema({
    ip: String,
    port: Number,
    banner: String,
    status: String,
    lastScan: Date
});

schemas.serverQuery = new mongoose.Schema({
    ip: String,
    successful: Boolean,
    data: JSON,
    date: Date,
})

module.exports = schemas;