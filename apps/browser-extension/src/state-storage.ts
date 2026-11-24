const key = 'controlState';
const store = 'state';
let database: Promise<IDBDatabase> | undefined;
let migration: Promise<void> | undefined;

function openDatabase() {
  return database ??= new Promise<IDBDatabase>((resolve, reject) => {
    const request = indexedDB.open('zekvar-browser', 1);
    request.onupgradeneeded = () => request.result.createObjectStore(store);
    request.onerror = () => reject(request.error);
    request.onsuccess = () => {
      const connection = request.result;
      connection.onclose = () => { database = undefined; };
      connection.onversionchange = () => {
        connection.close();
        database = undefined;
      };
      resolve(connection);
    };
  }).catch((error) => {
    database = undefined;
    throw error;
  });
}

export async function readWorkerState<T>(): Promise<T | undefined> {
  const connection = await openDatabase();
  return new Promise((resolve, reject) => {
    const transaction = connection.transaction(store, 'readonly');
    const request = transaction.objectStore(store).get(key);
    transaction.oncomplete = () => resolve(request.result as T | undefined);
    transaction.onabort = () => reject(transaction.error);
  });
}

export async function saveWorkerState(state: unknown): Promise<void> {
  const connection = await openDatabase();
  return new Promise((resolve, reject) => {
    const transaction = connection.transaction(store, 'readwrite', { durability: 'strict' });
    transaction.objectStore(store).put(state, key);
    transaction.oncomplete = () => resolve();
    transaction.onabort = () => reject(transaction.error);
  });
}

export async function restrictChromeStorage(area: chrome.storage.StorageArea) {
  try {
    if (typeof area.setAccessLevel !== 'function') return false;
    await area.setAccessLevel({ accessLevel: 'TRUSTED_CONTEXTS' });
    return true;
  } catch {
    return false;
  }
}

export function migrateWorkerState() {
  return migration ??= (async () => {
    await restrictChromeStorage(chrome.storage.local);
    const legacy = (await chrome.storage.local.get(key))[key];
    if (legacy === undefined) return;
    // The private write must commit before removing the old copy. A retry keeps the committed copy.
    if (await readWorkerState() === undefined) await saveWorkerState(legacy);
    await chrome.storage.local.remove(key);
  })().catch((error) => {
    migration = undefined;
    throw error;
  });
}
