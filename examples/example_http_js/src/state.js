/*
    The goal of this group of route is to test an access to the disk
*/

import { readFile, writeFile, access } from 'fs/promises'

import { Router } from 'express'
import { buildUrl } from './helpers.js'

const fileExists = async (path) => { 
    try {
        await access(path)
        return true
    } catch (error) {
        return false
    }
}

const toStorage = counter => JSON.stringify({counter})
const COUNTER_PATH = '/var/lib/example/storage.json'
const state = Router()

state.use(async (req, _res, next) => {
    const exists = await fileExists(COUNTER_PATH)
    if(!exists){
        await writeFile(COUNTER_PATH, toStorage(0))
        req.counter = 0
        return next()
    }

    const f = await readFile(COUNTER_PATH)
    try{
        const { counter } = JSON.parse(f)
        req.counter = counter
    }
    catch(err){
        console.log(err)
        req.counter = 0
    }
    return next()
})

state.get('/', async (req, res) => {
    res.send({
        counter: req.counter,
        increment: buildUrl(req, 'state/increment'),
        decrement: buildUrl(req, 'state/decrement')
    })
})

state.get('/increment', async (req, res) => {
    const counter = req.counter + 1
    await writeFile(COUNTER_PATH, toStorage(counter))
    return res.send({counter})
})

state.get('/decrement', async (req, res) => {
    const counter = req.counter - 1
    await writeFile(COUNTER_PATH, toStorage(counter))
    return res.send({counter})
})

export default state