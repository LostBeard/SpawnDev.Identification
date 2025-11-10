using SpawnDev.BlazorJS;

namespace SpawnDev.Identification
{
    /// <summary>
    /// ECDSA signature token and metadata.<br/>
    /// All properties are included except Token when the signature (token) is calculated.
    /// </summary>
    public class Signature
    {
        /// <summary>
        /// Signing algorithm name
        /// </summary>
        public string Alg { get; set; } = "";
        /// <summary>
        /// Signing hash name
        /// </summary>
        public string HashName { get; set; } = "";
        /// <summary>
        /// The generated signature
        /// </summary>
        public string Token { get; set; } = "";
        /// <summary>
        /// The public key of the signee
        /// </summary>
        public string PublicKey { get; set; } = "";
        /// <summary>
        /// When the token was signed
        /// </summary>
        public EpochDateTime TokenSigned { get; set; } = default!;
        /// <summary>
        /// If not null, this is when the token expires
        /// </summary>
        public EpochDateTime? TokenExpiration { get; set; }
        /// <summary>
        /// Claims specific to this signature
        /// </summary>
        public Dictionary<string, string> Claims { get; set; } = new Dictionary<string, string>();
    }
}
