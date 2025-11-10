using SpawnDev.BlazorJS.Cryptography;
using SpawnDev.BlazorJS.Cryptography.BrowserWASM;
using SpawnDev.BlazorJS.JSObjects;

namespace SpawnDev.Identification
{
    /// <summary>
    /// This IPortableKeyStore supports basic key storage and retrieval in a web browser.<br/>
    /// This storage supports non-extractable keys.
    /// </summary>
    public class IndexedDBKeyStore : IPortableKeyStore
    {
        /// <summary>
        /// The database name used for storage<br/>
        /// </summary>
        public string DBName { get; private set; }
        /// <summary>
        /// The object store name used for storage<br/>
        /// </summary>
        public string StoreName { get; private set; }
        /// <summary>
        /// Creates a new BrowserWASMPortableKeyStore instance<br/>
        /// </summary>
        /// <param name="dbName"></param>
        /// <param name="storeName"></param>
        public IndexedDBKeyStore(string? dbName = null, string? storeName = null)
        {
            DBName = string.IsNullOrEmpty(dbName) ? nameof(IndexedDBKeyStore) : dbName;
            StoreName = string.IsNullOrEmpty(storeName) ? nameof(IndexedDBKeyStore) : storeName;
        }
        /// <summary>
        /// Gets the IndexedDB database instance<br/>
        /// </summary>
        /// <returns></returns>
        async Task<IDBDatabase> GetDB()
        {
            using var idbFactory = new IDBFactory();
            var idb = await idbFactory.OpenAsync(DBName, 1, (evt) =>
            {
                // upgrade needed
                using var request = evt.Target;
                using var db = request.Result;
                var stores = db.ObjectStoreNames;
                if (!stores.Contains(StoreName))
                {
                    using var myKeysStore = db.CreateObjectStore<string, CryptoKeyPair>(StoreName);
                }
            });
            return idb;
        }
        /// <summary>
        /// Returns true if the key store database exists<br/>
        /// </summary>
        /// <returns></returns>
        public async Task<bool> DBExists()
        {
            using var idbFactory = new IDBFactory();
            var databases = await idbFactory.Databases();
            return databases.Any(db => db.Name == DBName);
        }
        /// <summary>
        /// Returns true if the key store and database exists<br/>
        /// </summary>
        /// <returns></returns>
        public async Task<bool> Exists()
        {
            using var idbFactory = new IDBFactory();
            var databases = await idbFactory.Databases();
            var dbExists = databases.Any(db => db.Name == DBName);
            if (!dbExists) return false;
            using var idb = await idbFactory.OpenAsync(DBName);
            return idb.ObjectStoreNames.Contains(StoreName);
        }
        /// <summary>
        /// Returns true if a key with the given name exists<br/>
        /// </summary>
        /// <param name="name"></param>
        /// <returns></returns>
        public async Task<bool> Exists(string name)
        {
            var storeExists = await Exists();
            if (!storeExists) return false;
            using var idb = await GetDB();
            using var tx = idb.Transaction(StoreName);
            using var objectStore = tx.ObjectStore<string, CryptoKeyPair>(StoreName);
            var namesArray = await objectStore.GetAllKeysAsync();
            var names = namesArray.ToArray();
            return names.Contains(name);
        }
        /// <summary>
        /// Clears the key store<br/>
        /// </summary>
        /// <returns></returns>
        public async Task Clear()
        {
            using var idb = await GetDB();
            using var tx = idb.Transaction(StoreName);
            using var objectStore = tx.ObjectStore<string, CryptoKeyPair>(StoreName);
            await objectStore.ClearAsync();
        }
        /// <summary>
        /// Gets a CryptoKeyPair by name or null if not found<br/>
        /// </summary>
        /// <param name="name"></param>
        /// <returns></returns>
        public async Task<T?> Get<T>(string name) where T : PortableKey
        {
            using var idb = await GetDB();
            using var tx = idb.Transaction(StoreName);
            using var objectStore = tx.ObjectStore<string, CryptoKeyPair>(StoreName);
            var keyPair = await objectStore.GetAsync(name);
            if (keyPair == null) return null;
            if (typeof(T) == typeof(PortableAESCBCKey) || typeof(T) == typeof(BrowserWASMAESCBCKey))
            {
                return (T)(PortableKey)new BrowserWASMAESCBCKey(keyPair.PrivateKey!);
            }
            else if (typeof(T) == typeof(PortableAESGCMKey) || typeof(T) == typeof(BrowserWASMAESGCMKey))
            {
                // TODO - read meta info needed also
                throw new NotImplementedException();
                return (T)(PortableKey)new BrowserWASMAESCBCKey(keyPair.PrivateKey!);
            }
            else if (typeof(T) == typeof(PortableECDHKey) || typeof(T) == typeof(BrowserWASMECDHKey))
            {
                return (T)(PortableKey)new BrowserWASMECDHKey(keyPair);
            }
            else if (typeof(T) == typeof(PortableECDSAKey) || typeof(T) == typeof(BrowserWASMECDSAKey))
            {
                return (T)(PortableKey)new BrowserWASMECDSAKey(keyPair);
            }
            throw new NotSupportedException();
        }
        /// <summary>
        /// Sets a CryptoKeyPair by name<br/>
        /// </summary>
        /// <param name="name"></param>
        /// <param name="keys"></param>
        /// <returns></returns>
        public async Task Set(string name, PortableKey keys)
        {
            CryptoKeyPair? keyPair = null;
            if (keys is BrowserWASMAESCBCKey wasmCBC)
            {
                keyPair = new CryptoKeyPair
                {
                    PrivateKey = wasmCBC.Key
                };
            }
            else if (keys is BrowserWASMAESGCMKey wasmGCM)
            {
                // TODO - store the nonce size and tag size with the key
                throw new NotImplementedException();
                keyPair = new CryptoKeyPair
                {
                    PrivateKey = wasmGCM.Key
                };
            }
            else if (keys is BrowserWASMECDHKey wasmECDH)
            {
                keyPair = wasmECDH.Key;
            }
            else if (keys is BrowserWASMECDSAKey wasmECDSA)
            {
                keyPair = wasmECDSA.Key;
            }
            else
            {
                throw new NotImplementedException();
            }
            if (keyPair == null)
            {
                throw new ArgumentNullException(nameof(keys));
            }
            using var idb = await GetDB();
            using var tx = idb.Transaction(StoreName, true);
            using var objectStore = tx.ObjectStore<string, CryptoKeyPair>(StoreName);
            await objectStore.PutAsync(keyPair, name);
        }
        /// <summary>
        /// Removes a CryptoKeyPair by name<br/>
        /// </summary>
        /// <param name="name"></param>
        /// <returns></returns>
        public async Task Remove(string name)
        {
            using var idb = await GetDB();
            using var tx = idb.Transaction(StoreName, true);
            using var objectStore = tx.ObjectStore<string, CryptoKeyPair>(StoreName);
            await objectStore.DeleteAsync(name);
        }
        /// <summary>
        /// Lists all stored key names<br/>
        /// </summary>
        /// <returns></returns>
        public async Task<string[]> List()
        {
            using var idb = await GetDB();
            using var tx = idb.Transaction(StoreName, false);
            using var objectStore = tx.ObjectStore<string, CryptoKeyPair>(StoreName);
            var keysArray = await objectStore.GetAllKeysAsync();
            var keys = keysArray.ToArray();
            return keys;
        }
    }
}

