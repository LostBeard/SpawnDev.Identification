namespace SpawnDev.Identification
{
    /// <summary>
    /// A signable object
    /// </summary>
    public class SignedObject : ClaimsObject
    {
        /// <summary>
        /// ECDSA Signatures
        /// </summary>
        public List<Signature> Signatures { get; set; } = new List<Signature>();
    }
    /// <summary>
    /// A signable object with a value of type T
    /// </summary>
    /// <typeparam name="T"></typeparam>
    public class SignedObject<T> : SignedObject
    {
        /// <summary>
        /// Cast a value of type T to SignedObject&let;T>
        /// </summary>
        /// <param name="value"></param>
        public static explicit operator SignedObject<T>(T value) => new SignedObject<T>(value);
        /// <summary>
        /// Cast to value of type T
        /// </summary>
        /// <param name="signedObject"></param>
        public static explicit operator T(SignedObject<T> signedObject) => signedObject.Value;
        /// <summary>
        /// Value
        /// </summary>
        public T Value { get; set; } = default!;
        public SignedObject() { }
        public SignedObject(T value) => Value = value;
    }
}
