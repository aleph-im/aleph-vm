import { readdir } from 'fs/promises'
import { join, dirname } from 'path'
import { fileURLToPath } from 'url'
import { exec } from 'child_process'

import express from 'express'
import axios from 'axios'
import { post, accounts } from 'aleph-sdk-ts'
import { buildUrl } from './helpers.js'
import state from './state.js'

const PORT = process.env.PORT || 3000
const app = express()

// `account` and `mnemonic` are stored as global variables
// They are reassigned using `newRandomKeypair`
// and used in the /new_keypair and /post_aleph_message endpoints
let account, mnemonic
const newRandomKeypair = async () => {
  console.log('Creating an ephemeral keypair...')
  const ethAccountWrapper = await accounts.ethereum.NewAccount()
  account = ethAccountWrapper.account
  mnemonic = ethAccountWrapper.mnemonic
  console.log('Here is your mnemonic:')
  console.log(mnemonic)
}

// A keypair is generated during boot
await newRandomKeypair()

app.use(express.json())

// Just a simple query logger
app.use((req, _res, next) => {
  console.log(`[${new Date().toISOString()}] ${req.method.padEnd(8, ' ')} ${req.url}`)
  return next()
})

app.get('/', async (req, res) => {
  const files = await readdir('/opt')
  const endpoints = {
    env: 'Lists environment variables',
    messages: 'Read data from Aleph using the Aleph client library',
    internet: 'Read data from the public Internet using an http request',
    http_post: 'Posts data from a form to this server',
    post_aleph_message: 'Posts a message on the Aleph network',
    new_keypair: 'Simple counter state machine',
    raise: 'Raises an error to check that the init handles it properly without crashing',
    crash: 'Crash the entire VM in order to check that the supervisor can handle it',
    state: 'Stores a simple counter on disk'
  }

  return res.send({
    endpoints: Object.entries(endpoints)
              .map(([name, description]) => ({
                name,
                url: buildUrl(req, name),
                description
              })),
    files
  })
})

app.use('/state', state)

app.get('/env', (_req, res) => {
  return res.send(process.env)
})

app.get('/messages', async (_req, res) => {
  console.log('Fetching messages on the Aleph network...')
  try {
    console.time('Fetching message')
    const posts = await post.Get({
      APIServer: "https://api2.aleph.im",
      hashes: ['f246f873c3e0f637a15c566e7a465d2ecbb83eaa024d54ccb8fb566b549a929e'],
      refs: [],
      addresses: [],
      tags: [],
      channel: []
    })
    console.timeEnd('Fetching message')
    console.log('Message fetched succesfully')
  
    return res.send(posts)
  } catch (error) {
    console.log(error)
    return res.status(500).send({ error: 'An error occured while fetching the messages' })
  }
})

app.get('/internet', async (_req, res) => {
  try {
    console.time('HTTP request')
    const URL = 'https://aleph.im'

    // Axios is a dependency of the Aleph SDK
    // So we do not need to install it
	  const request = await axios.get(URL)
    console.timeEnd('HTTP request')

    // Replacing script source so it does not point out to localhost
    const jsRE = /assets\/(css|js)\/([\w\.\-]+)\.(js|css)/gi
    let data = request.data.replace(jsRE, `${URL}/assets/$1/$2.$3`)
    return res.send(data)
  } catch (error) {
    console.log(error)
    res.status(500).send({ error: 'An error occured while trying to access the internet'})
  }
})

app.get('/http_post', (_req, res) => {
  return res.sendFile(join(dirname(fileURLToPath(import.meta.url)), 'templates/post-message.html'))
})

app.post('/http_post', (req, res) => {
  const { data } = req.body
  return res.send({ data })
})

app.get('/post_aleph_message', async (req, res) => {
  try{
    const msg = await post.Publish({
      APIServer: "https://api2.aleph.im",
      account,
      postType: 'DEMO',
      channel: 'Aleph-VM',
      inlineRequested: true,
      storageEngine: 'inline',
      content: {
        text: 'This was posted from the Aleph VM Node.js demo',
      }
    })

    return res.send({
      status: 'sent',
      hash: msg.item_hash,
      address: account.address
    })
  }
  catch(error){
    console.log(error)
    return res.send({ error: 'An error occured while sending the message' })
  }
})

app.get('/new_keypair', async (_req, res) => {
  try {
    await newRandomKeypair()

    return res.send({ 
      info: 'New keypair generated on the server',
      address: account.address
    })
  } catch (error) {
    console.log(error)
    
    return res.send({ error: 'Could not generate a new random keypair' })
  }
})

app.get('/raise', () => { 
  try {
	  throw new Error('This error was raised on purpose')
  } catch (error) {
    console.log(error)
    process.exit(1)
  }
})

app.get('/crash', () => {
  exec('kill -9 -1')
})

app.listen(PORT, () => console.log(`Listening on port ${PORT}`))