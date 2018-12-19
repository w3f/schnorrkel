# schnorr-dalek

Right now, this crate is only an experiment in how best to present Schnorr signatures with Ristretto compressed Ed25519 points.  It includes some useful tricks for interacting with Ed25519, mostly via ed25519-dalek, of which this crate is a fork.

First, we adjust the naming of secret key types to encourage using only ed25519 expanded secret keys, which permits us to retain the "clamping" in the expansion of ed25519 secret keys, while never encountering "clamping" in more serious operations.  In particular, our `MiniSecretKey` serialize as ed25519 secret keys and indeed are `ed25519_dalek::SecretKey`s.  We "clamp" *only* in `MiniSecretKey::expand` but nothing algebraic involves `MiniSecretKey`s anyways, so no problems arise.

Second, we serialize our `SecretKey`s as ed25519 expanded secret keys as well, meaning they can easily be converted into `ed25519_dalek::ExpandedSecretKey`s.  Internally however, our `SecretKey`s are true scalars mod l, not scalars mod 8*l like `ed25519_dalek::SecretKey`s.  We achieve this by simply multiplying by the the scalar by the cofactor when serialising `SecretKeys` and dividing by the cofactor when deserialising `SecretKeys`.  

As a result, there are no strange corner cases when doing algebra between the scalars and curve points without 2-torsion.  Among other things, we therefore have hierarchical key derivation for both our signature scheme, and even for ed25519 itself.

Third, we serialize all curve points using Ristretto, which ensures the curve points are 2-torsion free.  We can export ed25519 public keys quickly by merely multiplying by the cofactor 8.  We can also import ed25519 public keys too, but only at extreme cost of two scalar multiplications, a 2-torsion freeness check and a multiplication by one eighth.  As such, any protocols using this library are *strongly* encouraged to use only the Ristretto wire format, not ed25519.



