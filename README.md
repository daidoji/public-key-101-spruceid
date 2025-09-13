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

I'm sad to say I didn't quite make it through the greenfield example here which I'm submitting.  I was advised to pick a statically typed language and Rust was the one I'd used most recently so I figured I'd attempt the solution in Rust and spent 3 hours yesterday and another 3 hours today (Friday 12-Sep-25) and got as far as this although I may work on it a bit more this weekend to see if I can finish it up just to get the Rust reps and for my own edification.

Ultimately the time was spent in figuring out a lot of Rust issues and Rocket framework and packages to use and I didn't come in on time even though I used a few extra hours to try and get done.  

# Use 

It was intended to be used via: 
1. `cargo --bin server` Starting a rocket web framework server that has an api like
  * `/` index request that returns some information about the api
  * `/present-did-key/<did_key_uri>` - an api to present a did:key uri and receive a nonce
  * `/verify-nonce/<did_key_uri>/<nonce>` - an api to present the did:key and associated nonce and return "verified" or "not verified"
2. `cargo --bin client` A short script that takes a pre-defined did:key, requests a nonce from the server for a given did:key, signs a payload proving that they hold that key (within a certain duration to be set at server configuration time to prevent stale nonces) and then remove that nonce from the server to prevent replay attacks (as well as using the TextNonce itself)

Right now these scripts don't do much although they have code (no tests) showing my partial solution.

TLS (not mutual) would have been used to secure the calls to and from the server with the did key to verify and simple get request API bc I was just trying to get something working.  Honestly, RFC 9421 or something like that probably should be used in a real project but I was struggling to get it completed and didn't quite get there.

It uses the default Ed25519 default key of the did:key crate but supports the multiple key types that that crate supports.

# Caveats

* did:key crate is kind of weird.  Probably should be audited a bit more before being used in production.  It claims no dependencies but then has a ton of dependencies.
* I'm not entirely sure this is the right way to go about it or if this is necessarily secure.  Putting the nonce in the http payload might be safer but I was just going to sign a padded (did:key | nonce) pulled from the request itself.  Maybe I should use an hmac, idk.  These are things I'd have to think about a lot and double check with real life cryptographers before I'd feel comfortable with it being secure.
* Similarly with the choice of crates and packages.  Rust is supposed to be more secure but I honestly picked TextNonce because it seemed reasonable from the description as well as the Rocket Web Framework and other crate choices.  I'd probably have to understand these crates a lot more before I was comfortable with them from a security context in production.
* Key impersonation attacks are probably still possible if a nonce is held onto by the holder for a long time before verifying and an attacker compromises the value and the key although I was planning on adding a Duration timeout.  
* The State in rocketchat is async and I tried to use a concurrent hashmap to mitigate issues but if the attacker can compromise the key and nonce and submit within a time window that the actual holder submits can probably verify a payload without the holder or verifier necessarily being aware because I didn't have time to fully grasp the concurrency garuntees of the Dhashmap.
