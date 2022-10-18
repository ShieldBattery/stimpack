const fs = require('fs')
const path = require('path')

const orig = path.join('.', 'native', 'index.node')
if (!fs.existsSync(orig)) {
  throw new Error('there is no ./native/index.node built by Neon to mark as prebuild')
}

const prebuildDir = path.join('.', 'prebuilds')
fs.mkdirSync(prebuildDir, { recursive: true })
const dest = path.join(prebuildDir, 'x64.node')
fs.copyFile(orig, dest, err => {
  if (err) {
    throw err
  }
})
