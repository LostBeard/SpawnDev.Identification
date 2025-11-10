using SpawnDev.BlazorJS.Cryptography;
using System.Text;
using System.Text.Json;

namespace SpawnDev.Identification
{
    public class FileSystemKeyStore : IPortableKeyStore
    {
        /// <summary>
        /// The database name used for storage<br/>
        /// </summary>
        public string DBName { get; private set; }
        /// <summary>
        /// App data path used by this service
        /// </summary>
        public string AppDataPath { get; private set; }
        IPortableCrypto PortableCrypto;
        public FileSystemKeyStore(IPortableCrypto portableCrypto, string? appDataPath = null, string? storeName = null)
        {
            PortableCrypto = portableCrypto;
            if (string.IsNullOrWhiteSpace(appDataPath))
            {
                var userProfilePath = Environment.GetFolderPath(Environment.SpecialFolder.UserProfile);
                if (string.IsNullOrEmpty(userProfilePath))
                {
                    userProfilePath = Environment.GetFolderPath(Environment.SpecialFolder.CommonApplicationData);
                }
                appDataPath = Path.Combine(userProfilePath, $".{AppDomain.CurrentDomain.FriendlyName}");
            }
            AppDataPath = appDataPath;
            if (!Directory.Exists(AppDataPath))
            {
                Directory.CreateDirectory(AppDataPath);
            }
            if (string.IsNullOrWhiteSpace(storeName)) storeName = "leaf";
            DBName = Path.Combine(AppDataPath, storeName);
            if (!Directory.Exists(DBName))
            {
                Directory.CreateDirectory(DBName);
            }
        }
        PortableAESCBCKey? jKey = null;
        Task? _Ready = null;
        Task Ready => _Ready ??= Init();
        async Task Init()
        {
            var fPath = Path.Combine(AppDataPath, await E("root", true));
            if (File.Exists(fPath))
            {
                try
                {
                    var bytes = File.ReadAllBytes(fPath).Reverse().ToArray();
                    jKey = await PortableCrypto.ImportAESCBCKey(bytes);
                }
                catch { }
            }
            if (jKey == null)
            {
                jKey = await PortableCrypto.GenerateAESCBCKey(256);
                var bytes = await PortableCrypto.ExportAESCBCKey(jKey);
                File.WriteAllBytes(fPath, bytes.Reverse().ToArray());
            }
        }
        public async Task Clear()
        {
            var files = Directory.GetFiles(DBName);
            foreach (var file in files)
            {
                try
                {
                    File.Delete(file);
                }
                catch { }
            }
        }
        public async Task<bool> Exists(string name)
        {
            return File.Exists(await KeyPath(name));
        }
        public async Task<string[]> List()
        {
            var ret = new List<string>();
            var files = Directory.GetFiles(DBName);
            foreach (var file in files)
            {
                try
                {
                    var name = await D(file);
                    ret.Add(name);
                }
                catch { }
            }
            return ret.ToArray();
        }
        public async Task Remove(string name)
        {
            try
            {
                File.Delete(await KeyPath(name));
            }
            catch { }
        }
        private class SimpleKeyPair
        {
            public byte[]? PublicKey { get; set; }
            public byte[]? PrivateKey { get; set; }
        }
        public async Task<T?> Get<T>(string name) where T : PortableKey
        {
            await Ready;
            var filePath = await KeyPath(name);
            if (!File.Exists(filePath))
            {
                return null;
            }
            SimpleKeyPair? keyPair = null;
            byte[] data;
            try
            {
                data = File.ReadAllBytes(filePath);
                data = await D(data);
                keyPair = JsonSerializer.Deserialize<SimpleKeyPair>(data);
            }
            catch
            {
                return null;
            }
            if (keyPair == null || (keyPair.PrivateKey == null && keyPair.PublicKey == null)) return null;
            //
            if (typeof(PortableAESCBCKey).IsAssignableFrom(typeof(T)))
            {
                var k = await PortableCrypto.ImportAESCBCKey(keyPair.PrivateKey!);
                return (T)(PortableKey)k;
            }
            else if (typeof(PortableAESGCMKey).IsAssignableFrom(typeof(T)))
            {
                // TODO - read meta info needed also
                throw new NotImplementedException();
            }
            else if (typeof(PortableECDHKey).IsAssignableFrom(typeof(T)))
            {
                if (keyPair.PrivateKey != null && keyPair.PublicKey != null)
                {
                    var namedCurve = ECParser.GetSpkiECNamedCurve(keyPair.PublicKey!);
                    if (string.IsNullOrEmpty(namedCurve)) throw new Exception("Unknown named curve");
                    var k = await PortableCrypto.ImportECDHKey(keyPair.PublicKey, keyPair.PrivateKey, namedCurve);
                    return (T)(PortableKey)k;
                }
                else if (keyPair.PublicKey != null)
                {
                    var namedCurve = ECParser.GetSpkiECNamedCurve(keyPair.PublicKey!);
                    if (string.IsNullOrEmpty(namedCurve)) throw new Exception("Unknown named curve");
                    var k = await PortableCrypto.ImportECDHKey(keyPair.PublicKey, namedCurve);
                    return (T)(PortableKey)k;
                }
                else
                {
                    // when exported the public should have been set if the private was
                    throw new NotImplementedException();
                }
            }
            else if (typeof(PortableECDSAKey).IsAssignableFrom(typeof(T)))
            {
                if (keyPair.PrivateKey != null && keyPair.PublicKey != null)
                {
                    var namedCurve = ECParser.GetSpkiECNamedCurve(keyPair.PublicKey!);
                    if (string.IsNullOrEmpty(namedCurve)) throw new Exception("Unknown named curve");
                    var k = await PortableCrypto.ImportECDSAKey(keyPair.PublicKey, keyPair.PrivateKey, namedCurve);
                    return (T)(PortableKey)k;
                }
                else if (keyPair.PublicKey != null)
                {
                    var namedCurve = ECParser.GetSpkiECNamedCurve(keyPair.PublicKey!);
                    if (string.IsNullOrEmpty(namedCurve)) throw new Exception("Unknown named curve");
                    var k = await PortableCrypto.ImportECDSAKey(keyPair.PublicKey, namedCurve);
                    return (T)(PortableKey)k;
                }
                else
                {
                    // when exported the public should have been set if the private was
                    throw new NotImplementedException();
                }
            }
            throw new NotSupportedException();
        }
        public async Task Set(string name, PortableKey keys)
        {
            await Ready;
            SimpleKeyPair? keyPair = null;
            if (keys is PortableAESCBCKey pCBC)
            {
                keyPair = new SimpleKeyPair
                {
                    PrivateKey = await PortableCrypto.ExportAESCBCKey(pCBC)
                };
            }
            else if (keys is PortableAESGCMKey pGCM)
            {
                // TODO - store the nonce size and tag size with the key
                throw new NotImplementedException();
            }
            else if (keys is PortableECDHKey pECDH)
            {
                byte[]? privateKey = null;
                byte[]? publicKey = null;
                try
                {
                    privateKey = await PortableCrypto.ExportPrivateKeyPkcs8(pECDH);
                }
                catch { }
                try
                {
                    publicKey = await PortableCrypto.ExportPublicKeySpki(pECDH);
                }
                catch { }
                if (privateKey == null && publicKey == null) throw new Exception("Failed to save empty key");
                keyPair = new SimpleKeyPair
                {
                    PrivateKey = privateKey,
                    PublicKey = publicKey,
                };
            }
            else if (keys is PortableECDSAKey pECDSA)
            {
                byte[]? privateKey = null;
                byte[]? publicKey = null;
                try
                {
                    privateKey = await PortableCrypto.ExportPrivateKeyPkcs8(pECDSA);
                }
                catch { }
                try
                {
                    publicKey = await PortableCrypto.ExportPublicKeySpki(pECDSA);
                }
                catch { }
                if (privateKey == null && publicKey == null) throw new Exception("Failed to save empty key");
                keyPair = new SimpleKeyPair
                {
                    PrivateKey = privateKey,
                    PublicKey = publicKey,
                };
            }
            else
            {
                throw new NotImplementedException();
            }
            if (keyPair == null) throw new Exception("Set failed");
            var fPath = await KeyPath(name);
            var data = JsonSerializer.SerializeToUtf8Bytes(keyPair);
            data = await E(data);
            File.WriteAllBytes(fPath, data);
        }
        async Task<string> KeyPath(string name) => Path.Combine(DBName, await E(name));
        async Task<byte[]> D(byte[] value)
        {
            await Ready;
            var ret = await PortableCrypto.Decrypt(jKey!, value);
            return ret;
        }
        async Task<byte[]> E(byte[] value)
        {
            await Ready;
            var ret = await PortableCrypto.Encrypt(jKey!, value);
            return ret;
        }
        async Task<string> D(string value, bool simple = false)
        {
            var bytes = await D(Convert.FromHexString(value));
            if (simple) return Encoding.UTF8.GetString(bytes);
            await Ready;
            var ret = await PortableCrypto.Decrypt(jKey!, bytes);
            return Encoding.UTF8.GetString(ret);
        }
        async Task<string> E(string value, bool simple = false)
        {
            var bytes = Encoding.UTF8.GetBytes(value);
            if (simple) return Convert.ToHexString(bytes);
            await Ready;
            var ret = await PortableCrypto.Encrypt(jKey!, bytes);
            return Convert.ToHexString(ret);
        }
    }
}

