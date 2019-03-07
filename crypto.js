let cryp = require("crypto-browserify")
let bech32 = require("bech32")

let _ = require("lodash")
let hexEncoding = require("crypto-js/enc-hex")
let SHA256 = require("crypto-js/sha256")
let RIPEMD160 = require("crypto-js/ripemd160")
//let EC = require("elliptic")
//let EC = require("elliptic").EC
const CURVE = "secp256k1"

var EC = require("elliptic").ec

// Create and initialize EC context
// (better do it once and reuse it)
var ec = new EC("secp256k1")
//const ec = new EC(CURVE)
//const curve = new EC(CURVE)

/**
 * Performs a single SHA256.
 * @param {string} hex - String to hash
 * @returns {string} hash output
 */
let sha256 = hex => {
  if (typeof hex !== "string") throw new Error("sha256 expects a hex string")
  if (hex.length % 2 !== 0) throw new Error(`invalid hex string length: ${hex}`)
  const hexEncoded = hexEncoding.parse(hex)
  return SHA256(hexEncoded).toString()
}

/**
 * @param {arrayBuffer} arr
 * @returns {string} HEX string
 */
let ab2hexstring = arr => {
  if (typeof arr !== "object") {
    throw new Error("ab2hexstring expects an array")
  }
  let result = ""
  for (let i = 0; i < arr.length; i++) {
    let str = arr[i].toString(16)
    str = str.length === 0 ? "00" : str.length === 1 ? "0" + str : str
    result += str
  }
  return result
}

/**
 * Performs a SHA256 followed by a RIPEMD160.
 * @param {string} hex - String to hash
 * @returns {string} hash output
 */
let sha256ripemd160 = hex => {
  if (typeof hex !== "string")
    throw new Error("sha256ripemd160 expects a string")
  if (hex.length % 2 !== 0) throw new Error(`invalid hex string length: ${hex}`)
  const hexEncoded = hexEncoding.parse(hex)
  const ProgramSha256 = SHA256(hexEncoded)
  return RIPEMD160(ProgramSha256).toString()
}

/**
 * Encodes an address from input data bytes.
 * @param {string} value the public key to encode
 * @param {*} prefix the address prefix
 * @param {*} type the output type (default: hex)
 */
let encodeAddress = (value, prefix = "tbnb", type = "hex") => {
  const words = bech32.toWords(Buffer.from(value, type))
  return bech32.encode(prefix, words)
}

/**
 * Gets a private key from a keystore given its password.
 * @param {string} keystore the keystore in json format
 * @param {string} password the password.
 */
let getPrivateKeyFromKeyStore = (keystore, password) => {
  if (!_.isString(password)) {
    throw new Error("No password given.")
  }

  const json = _.isObject(keystore) ? keystore : JSON.parse(keystore)
  const kdfparams = json.crypto.kdfparams

  if (kdfparams.prf !== "hmac-sha256") {
    throw new Error("Unsupported parameters to PBKDF2")
  }

  const derivedKey = cryp.pbkdf2Sync(
    Buffer.from(password),
    Buffer.from(kdfparams.salt, "hex"),
    kdfparams.c,
    kdfparams.dklen,
    "sha256"
  )
  const ciphertext = Buffer.from(json.crypto.ciphertext, "hex")
  const bufferValue = Buffer.concat([derivedKey.slice(16, 32), ciphertext])
  const mac = sha256(bufferValue.toString("hex"))

  if (mac !== json.crypto.mac) {
    throw new Error("Key derivation failed - possibly wrong password")
  }

  const decipher = cryp.createDecipheriv(
    json.crypto.cipher,
    derivedKey.slice(0, 32),
    Buffer.from(json.crypto.cipherparams.iv, "hex")
  )
  const privateKey = Buffer.concat([
    decipher.update(ciphertext),
    decipher.final()
  ]).toString("hex")

  return privateKey
}

/**
 * Calculates the public key from a given private key.
 * @param {string} privateKeyHex the private key hexstring
 * @return {string} public key hexstring
 */
let getPublicKeyFromPrivateKey = privateKeyHex => {
  const curve = new EC(CURVE)
  const keypair = curve.keyFromPrivate(privateKeyHex, "hex")
  const unencodedPubKey = keypair.getPublic().encode("hex")
  return unencodedPubKey
}

/**
 * Gets an address from a public key hex.
 * @param {string} publicKeyHex the public key hexstring
 */
let getAddressFromPublicKey = publicKeyHex => {
  const pubKey = ec.keyFromPublic(publicKeyHex, "hex")
  const pubPoint = pubKey.getPublic()
  const compressed = pubPoint.encodeCompressed()
  const hexed = ab2hexstring(compressed)
  const hash = sha256ripemd160(hexed) // https://git.io/fAn8N
  const address = encodeAddress(hash)
  return address
}

/**
 * Gets an address from a private key.
 * @param {string} privateKeyHex the private key hexstring
 */
let getAddressFromPrivateKey = privateKeyHex => {
  return getAddressFromPublicKey(getPublicKeyFromPrivateKey(privateKeyHex))
}

let keystore
let password = "!)@(*#&kdfi!"
// let prk = getPrivateKeyFromKeyStore(keystore, password);
// let address = getAddressFromPrivateKey(prk)
// console.log('privateKey: ', prk, 'bnbaddress: ', address)

var fs = require("fs")
var path = require("path")

var root = path.join(__dirname)

readDirSync(root)
function readDirSync(path) {
  var pa = fs.readdirSync(path)
  pa.forEach(function(ele, index) {
    var info = fs.statSync(path + "/" + ele)
    if (info.isDirectory()) {
      console.log("dir: " + ele)
      readDirSync(path + "/" + ele)
    } else {
      if (ele.indexOf("keystore") > -1) {
        //console.log("file: "+ele)
        keystore = fs.readFileSync(ele, "utf-8")
        let prk = getPrivateKeyFromKeyStore(keystore, password)
        let address = getAddressFromPrivateKey(prk)
        //console.log('privateKey: ', prk, 'bnbaddress: ', address)
        //console.log(data);
        console.log(address)
      }
    }
  })
}
