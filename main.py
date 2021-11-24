from diffiehellman.diffiehellman import DiffieHellman

grab = DiffieHellman(18) # group 5, 14-18 primes
gojek = DiffieHellman(18)

grab.generate_public_key()    # automatically generates private key
gojek.generate_public_key()


print(len(str(grab.public_key)))
