# lamport
quantum resistant lamport and merkle tree signature functions (in progress)

Lamport one time signature scheme


Usage:

To create lamport key pairs:
  priv, pub = random_lkey()

To sign a message:
  sig = sign_lkey(priv, message)
 
To verify a signature:

  verify_lkey(sig, message, pub)
  
 Returns true or false.
 
 
