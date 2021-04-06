import rsa

a = [1,3,5]
hash = rsa.compute_hash(str(a).encode(), 'SHA-256')
print(str(a).encode())
print(hash.hex())
