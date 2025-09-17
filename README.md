# Assignment
The goal of this assignment is to implement a web service that proves ownership of a private key. It should be done in whatever language you're most comfortable with. 

Details:

    Two actors are involved: a holder, and a verifier web service.

    The holder should be a script that signs a payload with the private key and calls the verifier API.

    The verifier should provide an API that verifies the payload and signature to establish that the holder controls the private key.

    A nonce should be used to prevent replay of attestations.


Advice:

    If you are unable to implement a complete solution, write down your thoughts and explain the limitations of your solution.

    This assignment is fairly simple, and its purpose is mostly to show familiarity with Rust, backend development, and a basic understanding of public key cryptography.


This assignment should not take more than 4 hours. At the end you should send a link to a repo or a tarball of it, with a README with some instructions on how to run the demo.

# Approach

Honestly, in a production system I would reach for a tried and true protocol for key authentication like mutual TLS which in the Rocket Web Framework (which I picked at random) would apparently look like this example https://github.com/rwf2/Rocket/tree/master/examples/tls or some other battle tested protocol so I thought about just submitting this as my result.  A certificate is just a public key with some metadata and using mutual TLS would authenticate all payloads between the client in server for transparent web requests per the assignment.

However, I thought maybe it wasn't in the spirit of the project and so I thought I'd do something different and use a did:key provided through some out of band process to the server to sign the payload according to the project assignment.

1. Assume the client holds a did:key
2. The client presents that did:key urlencoded to the server via a GET request to the `/present-did-key/<urlencoded_did_key_uri>`
3. The server returns a nonce if its a valid did:key uri.
4. The client can then present the did:key and the nonce with the path `/validate-nonce/<urlencoded_did_key_uri>/<urlencoded_nonce>` alongside the header `did-key-signature` and the signature of the did:key over that same path encoded in base16 within five minutes of receiving that nonce.
5. If the nonce is valid, is timely (within the five minute window), and the signature verifies the server replies with "Valid" if not "Invalid"

# Use 

1. `cargo --bin server` Starting the server
2. `cargo --bin client` A short script that creates a did:key, requests a nonce from the server for that key, and then signs the payload as above to validate the nonce

It uses the default Ed25519 default key of the did:key crate but supports the multiple key types that that crate supports.

# Caveats

* This was originally a take-home problem for employment but then I finished it out to get the Rust practice in.  Def don't use this in production and my Rust is not great I'm sure.
* did:key crate is kind of weird.  Probably should be audited a bit more before being used in production.  It claims no dependencies but then has a ton of dependencies.
* I'm not entirely sure this is the right way to go about it or if this is necessarily secure.  Maybe this is at risk of some cryptographic attacks, idk.  These are things I'd have to think about a lot and double check with real life cryptographers and other security engineers before I'd feel comfortable with it being secure.
* Similarly with the choice of crates and packages.  Rust is supposed to be more secure but I honestly picked TextNonce because it seemed reasonable from the description as well as the Rocket Web Framework and other crate choices.  I'd probably have to understand these crates a lot more before I was comfortable with them from a security context in production.
* Key impersonation attacks are def possible.  We remove the nonce once its been validated but if the attacker can get the private key before the client validates the nonce there's really nothing to stop him.  
* Similarly mitm attacks.  TLS on rocket web framework should mitigate some of this risk, but there's no authentication on the key presented.
* Honestly, RFC 9421 or something is probably what I should use in the header signature but I've never really used it so just went with the simple solution.
* Base16 encoding for the signature and urlencoding for the URI request are both choices.  I'm not sure they're the right ones but they work.
