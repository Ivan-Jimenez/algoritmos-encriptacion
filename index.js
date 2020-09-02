/** AES */
const crypto = require('crypto');
const ENC_KEY = "bf3c199c2470cb477d907b1e0917c17b"; // set random encryption key
const IV = "5183666c72eec9e4"; // set random initialisation vector
// ENC_KEY and IV can be generated as crypto.randomBytes(32).toString('hex');

const stringToEncrypt = "Say hello to my little friend!";

const encryptAES = ((val) => {
  let cipher = crypto.createCipheriv('aes-256-cbc', ENC_KEY, IV);
  let encrypted = cipher.update(val, 'utf8', 'base64');
  encrypted += cipher.final('base64');
  return encrypted;
});

const decryptAES = ((encrypted) => {
  let decipher = crypto.createDecipheriv('aes-256-cbc', ENC_KEY, IV);
  let decrypted = decipher.update(encrypted, 'base64', 'utf8');
  return (decrypted + decipher.final('utf8'));
});

console.log('==================AES===============')
console.log('STRING:', stringToEncrypt)
const encryptedString = encryptAES(stringToEncrypt)
console.log('ENCRYPTED:', encryptedString)
console.log('DECRYPTED:', decryptAES(encryptedString))

/** RSA */
const { publicKey, privateKey } = crypto.generateKeyPairSync("rsa", {
	// The standard secure default length for RSA keys is 2048 bits
	modulusLength: 2048,
})

const encryptRSA = crypto.publicEncrypt(
	{
		key: publicKey,
		padding: crypto.constants.RSA_PKCS1_OAEP_PADDING,
		oaepHash: "sha256",
	},
	Buffer.from(stringToEncrypt)
)

// console.log("encypted data: ", encryptedData.toString("base64"))

const decryptRSA = crypto.privateDecrypt(
	{
		key: privateKey,
		padding: crypto.constants.RSA_PKCS1_OAEP_PADDING,
		oaepHash: "sha256",
	},
	encryptRSA
)

// console.log("decrypted data: ", decryptedData.toString())

console.log('==================RSA===============')
console.log('STRING:', stringToEncrypt)
console.log('ENCRYPTED:', encryptRSA.toString('base64'))
console.log('DECRYPTED:', decryptRSA.toString())