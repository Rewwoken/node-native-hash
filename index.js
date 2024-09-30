import { hashPassword, validatePassword } from './utils/hash.js';

const password = 'qwerty123';

const phcString = await hashPassword(password);
const isValid = await validatePassword(password, phcString);

console.log({ isValid });
