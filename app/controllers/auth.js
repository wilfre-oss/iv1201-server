const jwt = require('jsonwebtoken');
require('dotenv').config();
const database = require("../models");
const Person = database.person;

/**
 * Auth middleware which checks JWT of the request if there is one
 * repondes with either 401 if there is not JWT or 403 if invalid
 * @param {object} req - object of the request
 * @param {object} res -  object of the response
 * @param {function} next - function that calls next express function
 */
exports.verify = (req, res, next) => {
    const authHeader = req.headers['authorization']
    const token = authHeader && authHeader.split(' ')[1]

    if(token == null) return res.sendStatus(401)

    jwt.verify(token, process.env.TOKEN_SECRET, (err, username) => {
        if(err) return res.sendStatus(403)
        req.username = username
        next()
    })
}

/**
 * Auth middleware which checks JWT of the request if there is one
 * repondes with either 401 if there is not JWT or 403 if invalid
 * @param {object} req - object of the request
 * @param {object} res -  object of the response
 * @param {function} next - function that calls next express function
 */
exports.verifyRecruiter = async (req, res, next) => {
    const authHeader = req.headers['authorization']
    const token = authHeader && authHeader.split(' ')[1]

    if(token == null) {return res.sendStatus(401)}

    jwt.verify(token, process.env.TOKEN_SECRET, async (err, username) => {
        if(err) {return res.sendStatus(403)}
        try {
            const user = await Person.findOne({
                where: {
                    username: username
                }
            })
            if(user.role_id !== 1) {return res.sendStatus(403)}
        }
        catch (err) {
            return res.sendStatus(500)
        }
        next()
    })
}

/**
 * Auth middleware which checks JWT of the request if there is one
 * repondes with either 401 if there is not JWT or 403 if invalid
 * @param {object} req - object of the request
 * @param {object} res -  object of the response
 * @param {function} next - function that calls next express function
 */
exports.verifyApplicant = async (req, res, next) => {
    const authHeader = req.headers['authorization']
    const token = authHeader && authHeader.split(' ')[1]

    if(token == null) {return res.sendStatus(401)}

    jwt.verify(token, process.env.TOKEN_SECRET, async (err, username) => {
        if(err) {return res.sendStatus(403)}
        try {
            const user = await Person.findOne({
                where: {
                    username: username
                }
            })
            if(user.role_id !== 2) {return res.sendStatus(403)}
        }
        catch (err) {
            return res.sendStatus(500)
        }
        next()
    })
}


/**
 * The only purpose of this middleware is to send a 200 response
 * @param {object} req 
 * @param {object} res 
 */
exports.approve = async (req, res) => {
    res.sendStatus(200)
}

