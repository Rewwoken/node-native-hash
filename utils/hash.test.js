import { describe, it } from 'node:test';
import assert from 'node:assert';
import { hashPassword, validatePassword } from './hash.js';

const password = 'foo';
const wrongPassword = password + 'bar';
// TODO: improve params validation
const phcRegexp = /^\$scrypt\$.*\$.{43}\$.{86}$/;

describe('Password hashing and validation', () => {
	it('should return valid phc string', async () => {
		const phcString = await hashPassword(password);
		const invalidPhcString = phcString + 'baz';

		assert.match(phcString, phcRegexp);
		assert.doesNotMatch(invalidPhcString, phcRegexp);
	});

	it('should validate a correct password against its hash', async () => {
		const phcString = await hashPassword(password);
		const isValid = await validatePassword(password, phcString);

		assert.strictEqual(isValid, true, 'Password validation failed');
	});

	it('should fail validation with an incorrect password', async () => {
		const phcString = await hashPassword(password);
		const isValid = await validatePassword(wrongPassword, phcString);

		assert.strictEqual(
			isValid,
			false,
			'Validation should fail with incorrect password',
		);
	});

	it('should throw an error if PHC string has wrong algorithm', async () => {
		const phcString = await hashPassword(password);

		const parsed = phcString.split('$');
		parsed[1] = 'argon2i'; // [1] is algorithm name

		const invalidPhcString = parsed.join('$');

		await assert.rejects(
			validatePassword(password, invalidPhcString),
			new Error('Node.js crypto module only supports scrypt!'),
			'Expected an error for invalid algorithm',
		);
	});
});
