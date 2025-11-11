namespace SpawnDev.Identification
{
    /// <summary>
    /// A signable object
    /// </summary>
    public class ClaimsObject
    {
        /// <summary>
        /// Claims
        /// </summary>
        public Dictionary<string, List<string>> Claims { get; set; } = new Dictionary<string, List<string>>();
        /// <summary>
        /// Get
        /// </summary>
        /// <param name="key"></param>
        /// <returns></returns>
        public string? GetClaimFirstOrDefault(string key) => GetClaims(key)?.FirstOrDefault();
        /// <summary>
        /// Adds a claim with the specified key and value if it does not already exist
        /// </summary>
        /// <param name="key"></param>
        /// <param name="value"></param>
        public void AddClaim(string key, string value)
        {
            if (!Claims.TryGetValue(key, out var values))
            {
                values = new List<string>();
                Claims[key] = values;
            }
            var exists = values.Contains(value);
            if (!exists) values.Add(value);
        }
        /// <summary>
        /// Removes the claim with the specified key and value
        /// </summary>
        /// <param name="key"></param>
        /// <param name="value"></param>
        public void RemoveClaim(string key, string value)
        {
            if (Claims.TryGetValue(key, out var values))
            {
                Claims[key] = values.Where(o => o != value).ToList();
                if (!Claims[key].Any())
                {
                    Claims.Remove(key);
                }
            }
        }
        /// <summary>
        /// Removes all claims with the given key
        /// </summary>
        /// <param name="key"></param>
        public void RemoveClaims(string key)
        {
            if (Claims.ContainsKey(key))
            {
                Claims.Remove(key);
            }
        }
        /// <summary>
        /// Returns true if the claim key exists
        /// </summary>
        /// <param name="key"></param>
        /// <returns></returns>
        public bool ContainsClaim(string key) => Claims.ContainsKey(key);
        /// <summary>
        /// Returns true if the claim exists
        /// </summary>
        /// <param name="key"></param>
        /// <param name="value"></param>
        /// <returns></returns>
        public bool ContainsClaim(string key, string value) => GetClaims(key)?.Contains(value) ?? false;
        /// <summary>
        /// Returns a list of claim values with the specified key
        /// </summary>
        /// <param name="key"></param>
        /// <returns></returns>
        public List<string>? GetClaims(string key) => Claims?.TryGetValue(key, out var values) ?? false ? values : null;
    }
}
