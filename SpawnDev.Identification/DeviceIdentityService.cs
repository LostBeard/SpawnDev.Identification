using MessagePack;
using MessagePack.Resolvers;
using SpawnDev.BlazorJS;
using SpawnDev.BlazorJS.Cryptography;
using System.Text.Json;
using System.Text.RegularExpressions;

namespace SpawnDev.Identification
{
    /// <summary>
    /// Creates and manages a device identity for this browser/device<br/>
    /// </summary>
    public class DeviceIdentityService : IAsyncBackgroundService
    {
        public static readonly string DefaultHashName = "SHA-512";
        public static readonly string ECDHNamedCurve = "P-521";
        public static readonly string ECDSANamedCurve = "P-521";
        /// <summary>
        /// Device identity
        /// </summary>
        public DeviceIdentity Identity { get; private set; }
        /// <summary>
        /// Device user agent string
        /// </summary>
        public string UserAgent { get; }
        /// <inheritdoc/>
        public Task Ready => _Ready ??= InitAsync();
        private Task? _Ready = null;
        private BlazorJSRuntime JS;
        /// <summary>
        /// The SubtleCrypto object for performing cryptographic operations<br/>
        /// </summary>
        public IPortableCrypto? PortableCrypto { get; private set; }
        /// <summary>
        /// The devices ECDSA signing key pair<br/>
        /// </summary>
        public PortableECDSAKey? SigningKeys { get; set; }
        /// <summary>
        /// The devices ECDH asymmetric encryption key pair<br/>
        /// </summary>
        public PortableECDHKey? EncryptionKeys { get; set; }
        /// <summary>
        /// The CryptoKey store for storing keys<br/>
        /// </summary>
        public IPortableKeyStore KeyStore { get; }
        /// <summary>
        /// This instance's randomly generated identifier<br/>
        /// Not guaranteed to be unique<br/>
        /// </summary>
        public string InstanceId { get; }
        /// <summary>
        /// This device's public signing key hash<br/>
        /// </summary>
        public string PublicSigningKeyHash { get; private set; }
        /// <summary>
        /// This device's public signing key in base64 format<br/>
        /// </summary>
        public string PublicSigningKeyBase64 { get; private set; }
        /// <summary>
        /// This device's public signing key in hex format<br/>
        /// </summary>
        public string PublicSigningKeyHex { get; private set; }
        /// <summary>
        /// This device's public signing key as a byte array<br/>
        /// </summary>
        public byte[] PublicSigningKeyBytes { get; private set; }
        /// <summary>
        /// This device's public encryption key hash<br/>
        /// </summary>
        public string PublicEncryptionKeyHash { get; private set; }
        /// <summary>
        /// This device's public encryption key in base64 format<br/>
        /// </summary>
        public string PublicEncryptionKeyBase64 { get; private set; }
        /// <summary>
        /// This device's public encryption key in hex format<br/>
        /// </summary>
        public string PublicEncryptionKeyHex { get; private set; }
        /// <summary>
        /// This device's public encryption key as a byte array<br/>
        /// </summary>
        public byte[] PublicEncryptionKeyBytes { get; private set; }
        /// <summary>
        /// Creates a new DeviceIdentityService instance<br/>
        /// </summary>
        /// <param name="js"></param>
#pragma warning disable CS8618 // Non-nullable field must contain a non-null value when exiting constructor. Consider adding the 'required' modifier or declaring as nullable.
        public DeviceIdentityService(BlazorJSRuntime js, IPortableCrypto portableCrypto, IPortableKeyStore portableKeyStore)
#pragma warning restore CS8618 // Non-nullable field must contain a non-null value when exiting constructor. Consider adding the 'required' modifier or declaring as nullable.
        {
            JS = js;
            PortableCrypto = portableCrypto;
            InstanceId = JS.InstanceId;
            if (JS.IsBrowser)
            {
                UserAgent = JS.Get<string>("navigator.userAgent");
            }
            else
            {
                UserAgent = "app";
            }
            KeyStore = portableKeyStore;
        }
        private async Task InitAsync()
        {
            await InitKeys();
        }
        private async Task InitKeys()
        {
            if (PortableCrypto == null) throw new NullReferenceException();
            // try to load signing keys
            SigningKeys = await KeyStore.Get<PortableECDSAKey>(nameof(SigningKeys));
            // create new keys if needed
            if (SigningKeys == null)
            {
                SigningKeys = await GenerateECDSASigningKey();
                await KeyStore.Set(nameof(SigningKeys), SigningKeys);
            }
            PublicSigningKeyBytes = await PublicKeyToBytes(SigningKeys);
            PublicSigningKeyHash = ToHash(PublicSigningKeyBytes);
            PublicSigningKeyBase64 = ToBase64String(PublicSigningKeyBytes); ;
            PublicSigningKeyHex = ToHexString(PublicSigningKeyBytes);
            // try to load asymmetric encryption keys
            EncryptionKeys = await KeyStore.Get<PortableECDHKey>(nameof(EncryptionKeys));
            // create new keys if needed
            if (EncryptionKeys == null)
            {
                EncryptionKeys = await GenerateECDHEncryptionKey();
                await KeyStore.Set(nameof(EncryptionKeys), EncryptionKeys);
            }
            PublicEncryptionKeyBytes = await PublicKeyToBytes(EncryptionKeys);
            PublicEncryptionKeyHash = ToHash(PublicEncryptionKeyBytes);
            PublicEncryptionKeyBase64 = ToBase64String(PublicEncryptionKeyBytes);
            PublicEncryptionKeyHex = ToHexString(PublicEncryptionKeyBytes);
            // device name
            var deviceName = ""; // await Cache.ReadText("deviceName");
            if (string.IsNullOrEmpty(deviceName))
            {
                deviceName = PublicSigningKeyHash;
                //await Cache.WriteText("deviceName", deviceName);
            }
            // identity
            Identity = new DeviceIdentity
            {
                DeviceName = deviceName,
                UserAgent = UserAgent,
                InstanceId = InstanceId,
                Encrypt = PublicEncryptionKeyHex,
                Sign = PublicSigningKeyHex,
                SignHash = PublicSigningKeyHash,
                EncryptHash = PublicEncryptionKeyHash,
            };
#if DEBUG
            Log("Identity", Identity);
#endif
        }
        /// <summary>
        /// Fires when the identity is updated
        /// </summary>
        public event Action OnIdentityUpdated = default!;
        /// <summary>
        /// Sets the device name
        /// </summary>
        /// <param name="deviceName"></param>
        /// <returns></returns>
        public async Task SetDeviceName(string deviceName)
        {
            //await Cache.WriteText("deviceName", deviceName);
            Identity.DeviceName = deviceName;
            OnIdentityUpdated?.Invoke();
        }
        /// <summary>
        /// Generates a new ECDH key pair that can be used to derive a shared AES encryption key.<br/>
        /// If not extractable, the private key cannot be exported.<br/>
        /// To reuse the key pair, store it in the CryptoKeyStore.<br/>
        /// </summary>
        /// <returns></returns>
        public async Task<PortableECDHKey> GenerateECDHEncryptionKey(bool extractable = false)
        {
            return await PortableCrypto!.GenerateECDHKey(ECDHNamedCurve, extractable);
        }
        /// <summary>
        /// Generates an ECDSA signing key pair.<br/>
        /// If not extractable, the private key cannot be exported.<br/>
        /// To reuse the key pair, store it in the CryptoKeyStore.<br/>
        /// </summary>
        /// <param name="extractable"></param>
        /// <returns></returns>
        public async Task<PortableECDSAKey> GenerateECDSASigningKey(bool extractable = false)
        {
            return await PortableCrypto!.GenerateECDSAKey(ECDSANamedCurve, extractable);
        }
        /// <summary>
        /// Creates an ECDH public CryptoKey from an spki byte array<br/>
        /// </summary>
        /// <param name="spki"></param>
        /// <param name="extractable"></param>
        /// <returns></returns>
        /// <exception cref="Exception"></exception>
        public async Task<PortableECDHKey> PublicKeyECDHFrom(byte[] spki, bool extractable = true)
        {
            var namedCurve = ECParser.GetSpkiECNamedCurve(spki);
            if (string.IsNullOrEmpty(namedCurve)) throw new Exception("Invalid key");
            return await PortableCrypto!.ImportECDHKey(spki, namedCurve);
        }
        /// <summary>
        /// Creates an ECDSA public CryptoKey from an spki byte array<br/>
        /// </summary>
        /// <param name="spki"></param>
        /// <param name="extractable"></param>
        /// <returns></returns>
        /// <exception cref="Exception"></exception>
        public async Task<PortableECDSAKey> PublicKeyECDSAFrom(byte[] spki, bool extractable = true)
        {
            var namedCurve = ECParser.GetSpkiECNamedCurve(spki);
            if (string.IsNullOrEmpty(namedCurve)) throw new Exception("Invalid key");
            return await PortableCrypto!.ImportECDSAKey(spki, namedCurve);
        }
        /// <summary>
        /// Exports a private key to a pkcs8 formatted byte array.
        /// </summary>
        /// <param name="privateKey"></param>
        /// <returns></returns>
        public async Task<byte[]> PrivateKeyToBytes(PortableECDHKey privateKey)
        {
            return await PortableCrypto!.ExportPrivateKeyPkcs8(privateKey);
        }
        /// <summary>
        /// Exports a private key to a pkcs8 formatted byte array.
        /// </summary>
        /// <param name="privateKey"></param>
        /// <returns></returns>
        public async Task<byte[]> PrivateKeyToBytes(PortableECDSAKey privateKey)
        {
            return await PortableCrypto!.ExportPrivateKeyPkcs8(privateKey);
        }
        /// <summary>
        /// Creates a byte array from an EC public key
        /// </summary>
        /// <param name="publicKey"></param>
        /// <returns></returns>
        public async Task<byte[]> PublicKeyToBytes(PortableECDHKey publicKey)
        {
            return await PortableCrypto!.ExportPublicKeySpki(publicKey);
        }
        /// <summary>
        /// Creates a byte array from an EC public key
        /// </summary>
        /// <param name="publicKey"></param>
        /// <returns></returns>
        public async Task<byte[]> PublicKeyToBytes(PortableECDSAKey publicKey)
        {
            return await PortableCrypto!.ExportPublicKeySpki(publicKey);
        }
        /// <summary>
        /// Creates an ECDSA public CryptoKey from an spki hex formatted string<br/>
        /// </summary>
        /// <param name="spkiHex"></param>
        /// <param name="extractable"></param>
        /// <returns></returns>
        /// <exception cref="Exception"></exception>
        public async Task<PortableECDSAKey> PublicKeyECDSAFromHex(string spkiHex, bool extractable = true)
        {
            var publicKeyBytes = FromHexString(spkiHex);
            var namedCurve = ECParser.GetSpkiECNamedCurve(publicKeyBytes);
            if (string.IsNullOrEmpty(namedCurve)) throw new Exception("Invalid key");
            return await PortableCrypto!.ImportECDSAKey(publicKeyBytes, namedCurve, extractable);
        }
        /// <summary>
        /// Creates a signature on the provided object using the stored private key<br/>
        /// </summary>
        /// <typeparam name="T"></typeparam>
        /// <param name="obj"></param>
        /// <param name="expirationUtc"></param>
        /// <returns></returns>
        public Task Sign<T>(T obj, DateTime? expirationUtc = null, string? hashName = null) where T : SignedObject => Sign(SigningKeys!, obj, expirationUtc, hashName);
        /// <summary>
        /// Creates a signature on the provided object using the stored private key<br/>
        /// </summary>
        /// <typeparam name="T"></typeparam>
        /// <param name="obj"></param>
        /// <param name="expireFromNow"></param>
        /// <returns></returns>
        public Task Sign<T>(T obj, TimeSpan expireFromNow, string? hashName = null) where T : SignedObject => Sign(SigningKeys!, obj, expireFromNow, hashName);
        /// <summary>
        /// Creates a signature on the provided object using the provided private key<br/>
        /// </summary>
        /// <typeparam name="T"></typeparam>
        /// <param name="privateKey"></param>
        /// <param name="obj"></param>
        /// <param name="expireFromNow"></param>
        /// <returns></returns>
        public Task Sign<T>(PortableECDSAKey privateKey, T obj, TimeSpan expireFromNow, string? hashName = null) where T : SignedObject
            => Sign(privateKey, obj, DateTime.Now + expireFromNow, hashName);
        /// <summary>
        /// Creates a signature on the provided object using the provided private key<br/>
        /// </summary>
        /// <typeparam name="T"></typeparam>
        /// <param name="privateKey"></param>
        /// <param name="obj"></param>
        /// <param name="expirationUtc"></param>
        /// <returns></returns>
        public async Task Sign<T>(PortableECDSAKey privateKey, T obj, DateTime? expirationUtc = null, string? hashName = null) where T : SignedObject
        {
            var signature = new Signature
            {
                Alg = privateKey.AlgorithmName,
                HashName = string.IsNullOrEmpty(hashName) ? DefaultHashName : hashName,
                PublicKey = PublicSigningKeyHex,
                TokenSigned = DateTime.Now,
                TokenExpiration = expirationUtc,
            };
            obj.Signatures.Add(signature);
            // serialize in current state
            var data = Serialize(obj);
            var sig = await SignBase64(privateKey, data, signature.HashName);
            signature.Token = sig;
        }
        static MessagePackSerializerOptions Options = MessagePackSerializerOptions.Standard.WithResolver(CompositeResolver.Create(ContractlessStandardResolver.Instance, StandardResolver.Instance));
        /// <summary>
        /// Internal serialization method used for signing
        /// </summary>
        /// <param name="data"></param>
        /// <returns></returns>
        byte[] Serialize(object data)
        {
            return MessagePackSerializer.Serialize(data, Options);
        }
        /// <summary>
        /// Returns a fingerprint of a public hex string
        /// </summary>
        /// <param name="hex"></param>
        /// <param name="length"></param>
        /// <returns></returns>
        public string GetSignerHexKeyFingerprint(string hex, int length = 8)
        {
            var bytes = Convert.FromHexString(hex);
            var fingerprintBytes = bytes.SimpleCrc(length);
            return ToHexString(fingerprintBytes);
        }
        /// <summary>
        /// Creates a signature using the provided private key
        /// </summary>
        /// <param name="privateKey"></param>
        /// <param name="data"></param>
        /// <returns></returns>
        public async Task<string> SignBase64(PortableECDSAKey privateKey, byte[] data, string? hashName = null)
        {
            var bytes = await SignBytes(privateKey, data, hashName);
            return ToBase64String(bytes);
        }
        /// <summary>
        /// Creates a signature using the provided private key
        /// </summary>
        /// <param name="privateKey"></param>
        /// <param name="data"></param>
        /// <returns></returns>
        public async Task<byte[]> SignBytes(PortableECDSAKey key, byte[] data, string? hashName = null)
        {
            var arrayBufferSig = await Sign(key, data, hashName);
            return arrayBufferSig;
        }
        /// <summary>
        /// Creates a signature using the provided private key
        /// </summary>
        /// <param name="privateKey"></param>
        /// <param name="data"></param>
        /// <returns></returns>
        /// <exception cref="Exception"></exception>
        public async Task<byte[]> Sign(PortableECDSAKey key, byte[] data, string? hashName = null)
        {
            switch (key.AlgorithmName)
            {
                case "ECDSA":
                    return await PortableCrypto!.Sign(key, data, string.IsNullOrEmpty(hashName) ? DefaultHashName : hashName);
                default:
                    throw new Exception("Invalid keys");
            }
        }
        /// <summary>
        /// Creates a signature using the stored private key
        /// </summary>
        /// <param name="data"></param>
        /// <returns></returns>
        public Task<byte[]> Sign(byte[] data, string? hashName = null) => Sign(SigningKeys!, data, hashName);
        /// <summary>
        /// Verifies that all signatures on an object are valid<br/>
        /// Does not check who signed it, only that the signatures are valid<br/>
        /// </summary>
        /// <typeparam name="T"></typeparam>
        /// <param name="signedObject"></param>
        /// <param name="verifyTimestampIfExpirable"></param>
        /// <returns></returns>
        public async Task<bool> Verify<T>(T signedObject, bool verifyTimestampIfExpirable = true) where T : SignedObject
        {
            if (signedObject == null) return false;
            var sigs = signedObject.Signatures.ToList();
            signedObject.Signatures.Clear();
            foreach (var sig in sigs)
            {
                if (verifyTimestampIfExpirable && sig.TokenExpiration != null)
                {
                    var now = DateTime.Now;
                    if (now > sig.TokenExpiration)
                    {
                        return false;
                    }
                }
                using var signerKey = await PublicKeyECDSAFromHex(sig.PublicKey);
                var tokenToVerify = sig.Token;
                var hashName = sig.HashName;
                sig.Token = default!;
                signedObject.Signatures.Add(sig);
                // verify the token
                var serializedData = Serialize(signedObject);
                var verified1 = await Verify(signerKey, serializedData, tokenToVerify, hashName);
                if (!verified1) return false;
                sig.Token = tokenToVerify;
            }
            return true;
        }
        /// <summary>
        /// Verifies a signature using the stored public key
        /// </summary>
        /// <param name="data"></param>
        /// <param name="signature"></param>
        /// <returns></returns>
        public Task<bool> Verify(byte[] data, byte[] signature, string? hashName = null) => Verify(SigningKeys!, data, signature, hashName);
        /// <summary>
        /// Verifies a signature using the provided public key
        /// </summary>
        /// <param name="publicKey"></param>
        /// <param name="data"></param>
        /// <param name="base64Signature"></param>
        /// <returns></returns>
        public async Task<bool> Verify(PortableECDSAKey publicKey, byte[] data, string base64Signature, string? hashName = null)
        {
            var bytes = FromBase64String(base64Signature);
            return await Verify(publicKey, data, bytes, hashName);
        }
        /// <summary>
        /// Verifies a signature using the provided public key
        /// </summary>
        /// <param name="publicKey"></param>
        /// <param name="data"></param>
        /// <param name="signature"></param>
        /// <returns></returns>
        /// <exception cref="Exception"></exception>
        public async Task<bool> Verify(PortableECDSAKey publicKey, byte[] data, byte[] signature, string? hashName = null)
        {
            switch (publicKey.AlgorithmName)
            {
                case "ECDSA":
                    return await PortableCrypto!.Verify(publicKey, data, signature, string.IsNullOrEmpty(hashName) ? DefaultHashName : hashName);
                default:
                    throw new Exception("Invalid keys");
            }
        }
        string ToBase64String(byte[] bytes, bool safe = true) => safe ? ToBase64UrlSafe(bytes) : Convert.ToBase64String(bytes);
        byte[] FromBase64String(string base64Url) => FromBase64UrlSafe(base64Url);
        string ToHexString(byte[] bytes, bool toLower = true) => toLower ? Convert.ToHexString(bytes).ToLowerInvariant() : Convert.ToHexString(bytes);
        byte[] FromHexString(string value) => Convert.FromHexString(value);
        static Regex HexPattern = new Regex("^[0-9a-fA-F]+$", RegexOptions.Compiled);
        static readonly char[] padding = { '=' };
        /// <summary>
        /// Creates a base64 url safe string from a byte array<br/>
        /// </summary>
        /// <param name="toEncodeAsBytes"></param>
        /// <returns></returns>
        public string ToBase64UrlSafe(byte[] toEncodeAsBytes) => Convert.ToBase64String(toEncodeAsBytes).TrimEnd(padding).Replace('+', '-').Replace('/', '_');
        /// <summary>
        /// Creates a byte array from a base64 url safe string<br/>
        /// </summary>
        /// <param name="base64UrlSafe"></param>
        /// <returns></returns>
        public byte[] FromBase64UrlSafe(string base64UrlSafe)
        {
            string incoming = base64UrlSafe.Replace('_', '/').Replace('-', '+');
            switch (base64UrlSafe.Length % 4)
            {
                case 2: incoming += "=="; break;
                case 3: incoming += "="; break;
            }
            return Convert.FromBase64String(incoming);
        }
        /// <summary>
        /// Returns a 20 char hex string hash of the bytes
        /// </summary>
        /// <param name="key"></param>
        /// <returns></returns>
        public string ToHash(byte[] key)
        {
            return ToHexString(key.SimpleCrc(10));
        }
        void Log(params object[] data)
        {
            Console.WriteLine(JsonSerializer.Serialize(data));
        }
    }
}