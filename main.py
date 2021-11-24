from diffiehellman.diffiehellman import DiffieHellman

grab = DiffieHellman(18) # group 5, 14-18 primes
gojek = DiffieHellman(18)

grab.generate_public_key()    # automatically generates private key
gojek.generate_public_key()

grab.generate_shared_secret(gojek.public_key, echo_return_key=True)
gojek.generate_shared_secret(grab.public_key, echo_return_key=True)

print(len(str(grab.public_key)))
if grab.shared_secret == gojek.shared_secret:
    print('true')