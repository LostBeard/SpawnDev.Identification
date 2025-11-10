using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.DependencyInjection.Extensions;
using SpawnDev.BlazorJS;
using SpawnDev.BlazorJS.Cryptography;

namespace SpawnDev.Identification
{
    /// <summary>
    /// Extension methods
    /// </summary>
    public static class Extensions
    {
        /// <summary>
        /// Adds DeviceIdentityService platform specific Cryptography and key storage<br/>
        /// </summary>
        /// <param name="services"></param>
        /// <returns></returns>
        public static IServiceCollection AddDeviceIdentityService(this IServiceCollection services)
        {
            services.AddBlazorJSRuntime();
            if (OperatingSystem.IsBrowser())
            {
                services.TryAddSingleton<IPortableCrypto, BrowserWASMCrypto>();
                services.TryAddSingleton<IPortableKeyStore, IndexedDBKeyStore>();
            }
            else
            {
                services.TryAddSingleton<IPortableCrypto, DotNetCrypto>();
                services.TryAddSingleton<IPortableKeyStore, FileSystemKeyStore>();
            }
            services.TryAddSingleton<DeviceIdentityService>();
            return services;
        }
        /// <summary>
        /// Creates a simple checksum by folding the input byte array into a smaller byte array of the specified length.
        /// </summary>
        /// <param name="hash"></param>
        /// <param name="length"></param>
        /// <returns></returns>
        public static byte[] SimpleCrc(this byte[] hash, int length = 8)
        {
            if (hash.Length < length) return hash;
            var hashLength = hash.Length;
            var ret = new byte[length];
            for (var i = 0; i < hashLength; i++)
            {
                var n = i % length;
                ret[n] = (byte)(hash[i] + ret[n]);
            }
            return ret;
        }
    }
}
