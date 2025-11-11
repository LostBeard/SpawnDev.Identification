using SpawnDev.BlazorJS;

namespace SpawnDev.Identification
{
    /// <summary>
    /// ECDSA signature token and metadata.<br/>
    /// All properties are included except Token when the signature (token) is calculated.
    /// </summary>
    public class Signature : ClaimsObject
    {
        /// <summary>
        /// Signing algorithm name
        /// </summary>
        public string Alg { get; set; } = default!;
        /// <summary>
        /// Signing hash name
        /// </summary>
        public string HashName { get; set; } = default!;
        /// <summary>
        /// The generated signature
        /// </summary>
        public string Token { get; set; } = default!;
        /// <summary>
        /// The public key of the signee
        /// </summary>
        public string PublicKey { get; set; } = default!;
        /// <summary>
        /// When the token was signed
        /// </summary>
        public EpochDateTime TokenSigned { get; set; } = default!;
        /// <summary>
        /// If not null, this is when the token expires
        /// </summary>
        public EpochDateTime? TokenExpiration { get; set; }
    }
}
