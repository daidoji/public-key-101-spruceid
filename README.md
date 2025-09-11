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
