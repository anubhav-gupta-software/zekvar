import { send } from './protocol';

void send({ type: 'observe-app' }).catch(() => undefined);
