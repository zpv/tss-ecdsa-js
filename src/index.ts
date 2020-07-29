import { initKeygen, signMessage } from './bindings';

const MANAGER_URL = 'http://localhost:8001';

const data = initKeygen(MANAGER_URL, 1, 2);
console.log('Keygenned');
console.log(signMessage(data, MANAGER_URL, '0/0/0', 1, 2, 'hello'));
