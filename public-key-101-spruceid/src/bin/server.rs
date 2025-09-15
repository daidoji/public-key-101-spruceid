#[macro_use] extern crate rocket;

use std::time::{Instant,
                Duration};

use dashmap::DashMap;
use did_key::*;
use textnonce::TextNonce;
use rocket::State;

type DidKeyURI = String; // for semantic clarity

#[derive(Clone)]
struct NonceTime {
    nonce: String,
    time: Instant
}

struct NonceCache {
    cache: DashMap<DidKeyURI, NonceTime>
}

#[get("/")]
fn index() -> &'static str {
    return "PK 101 demo!\n/present_did_key/<did_key_uri>\n/validate_nonce/<did_key_uri>/<nonce>";
}

#[get("/present-did-key/<did_key_uri>")]
fn present_key(did_key_uri: &str, nonce_cache: &State<NonceCache>) -> String {
    // validate did_key uri by resolving it
    let _key = resolve(did_key_uri).expect("did:key should resolve correctly");
    let key_uri = "did:key:{key.fingerprint()}";
    // generate and store nonce for that key
    let nonce_time = NonceTime{nonce: TextNonce::new().into_string(),
                               time: Instant::now()};

    nonce_cache.cache.insert(key_uri.to_string(), nonce_time.clone());

    // respond with that nonce
    return nonce_time.nonce;
}

#[get("/validate-nonce/<did_key_uri>/<nonce_value>")]
fn validate_nonce(did_key_uri: &str, 
                  nonce_value: &str, 
                  nonce_cache: &State<NonceCache>) -> String 
{
    // did_key signed request and (this comes from Req Guard)
    //   nonce in cache and 
    //   its timely and 
    //   it is equivalent to nonce value provided
    
    fn check_nonce(nonce_time: NonceTime, nonce_value: &str) -> bool {
        nonce_time.nonce == nonce_value && 
            Instant::now() < nonce_time.time + Duration::new(60*5, 0)
    }

    match nonce_cache.cache.get(did_key_uri) {
        None => String::from("Invalid"),
        Some(nt) => if check_nonce(nt.clone(), nonce_value) { String::from("Valid") } else { String::from("Invalid") }
    }
}

#[launch]
fn rocket() -> _ {
    rocket::build().
        manage(NonceCache{cache: DashMap::new()}).
        mount("/", routes![index]).
        mount("/present-did-key/", routes![present_key]).
        mount("/validate-nonce/", routes![validate_nonce])
}
