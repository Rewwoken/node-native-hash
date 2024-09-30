import { randomBytes, scrypt, timingSafeEqual } from 'node:crypto';
import { promisify } from 'node:util';

const SALT_LEN = 32;
const KEY_LEN = 64;

const SCRYPT_PARAMS = {
	N: 32768,
	r: 8,
	p: 1,
	maxmem: 64 * 1024 * 1024,
};

// Promisified crypto functions
const randomBytesAsync = promisify(randomBytes);
const scryptAsync = promisify(scrypt);

// Hashing & validating
async function hashPassword(password) {
	const salt = await randomBytesAsync(SALT_LEN);
	const hash = await scryptAsync(password, salt, KEY_LEN, SCRYPT_PARAMS);

	return serializeHash(hash, salt, SCRYPT_PARAMS);
}

async function validatePassword(password, phcString) {
	const data = deserializeHash(phcString);
	const length = data.hash.length;

	const hash = await scryptAsync(password, data.salt, length, data.params);

	return timingSafeEqual(hash, data.hash);
}

// Serialization
async function serializeHash(hash, salt, params) {
	const paramsString = serializeHashParams(params);

	const saltString = salt.toString('base64').split('=')[0];
	const hashString = hash.toString('base64').split('=')[0];

	return `$scrypt$${paramsString}$${saltString}$${hashString}`;
}

function serializeHashParams(params) {
	const entries = Object.entries(params);
	const serialized = entries.map(([key, value]) => `${key}=${value}`);

	return serialized.join(',');
}

// Deserialization
function deserializeHash(phcString) {
	const [, algorithm, paramsString, salt, hash] = phcString.split('$');

	if (algorithm !== 'scrypt') {
		throw new Error('Node.js crypto module only supports scrypt!');
	}

	const paramsEntries = paramsString.split(',').map((param) => {
		const [key, value] = param.split('=');
		return [key, parseInt(value, 10)];
	});

	const params = Object.fromEntries(paramsEntries);
	const saltBuffer = Buffer.from(salt, 'base64');
	const hashBuffer = Buffer.from(hash, 'base64');

	return { algorithm, params, salt: saltBuffer, hash: hashBuffer };
}

export { hashPassword, validatePassword };
