function accessState({ write, state } = {}) {
  return new Promise((resolve, reject) => {
    const request = indexedDB.open('zekvar-browser', 1);
    request.onupgradeneeded = () => request.result.createObjectStore('state');
    request.onerror = () => reject(request.error);
    request.onsuccess = () => {
      const database = request.result;
      const transaction = database.transaction('state', write ? 'readwrite' : 'readonly');
      const store = transaction.objectStore('state');
      const result = write ? store.put(state, 'controlState') : store.get('controlState');
      transaction.oncomplete = () => { database.close(); resolve(result.result); };
      transaction.onabort = () => { database.close(); reject(transaction.error); };
    };
  });
}

export const readBrowserState = (worker) => worker.evaluate(accessState);
export const writeBrowserState = (worker, state) => worker.evaluate(accessState, { write: true, state });
