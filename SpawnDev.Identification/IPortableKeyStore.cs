using SpawnDev.BlazorJS.Cryptography;

namespace SpawnDev.Identification
{
    /// <summary>
    /// An minimal interface for a key store
    /// </summary>
    public interface IPortableKeyStore
    {
        /// <summary>
        /// Clear all keys
        /// </summary>
        /// <returns></returns>
        Task Clear();
        /// <summary>
        /// Returns true if the key exists
        /// </summary>
        /// <param name="name"></param>
        /// <returns></returns>
        Task<bool> Exists(string name);
        /// <summary>
        /// Gets the specified key
        /// </summary>
        /// <typeparam name="T"></typeparam>
        /// <param name="name"></param>
        /// <returns></returns>
        Task<T?> Get<T>(string name) where T : PortableKey;
        /// <summary>
        /// Returns a list of key names
        /// </summary>
        /// <returns></returns>
        Task<string[]> List();
        /// <summary>
        /// Removes a key
        /// </summary>
        /// <param name="name"></param>
        /// <returns></returns>
        Task Remove(string name);
        /// <summary>
        /// Saves a key
        /// </summary>
        /// <param name="name"></param>
        /// <param name="keys"></param>
        /// <returns></returns>
        Task Set(string name, PortableKey keys);
    }
}

