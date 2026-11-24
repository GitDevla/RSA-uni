import random


def extended_euclidean(a: int, b: int) -> tuple[int, int, int]:
    x0, y0 = 1, 0
    x1, y1 = 0, 1

    s = 1
    while b != 0:
        q, r = a // b, a % b
        a, b = b, r
        x0, x1 = x1, q * x1 + x0
        y0, y1 = y1, q * y1 + y0
        s = -s

    x0 = s * x0
    y0 = -s * y0

    return a, x0, y0


def pow_mod(a: int, n: int, m: int) -> int:
    res = 1
    a %= m
    while n > 0:
        if n % 2 == 1:
            res *= a
            res %= m
        a = (a * a) % m
        n >>= 1
    return res


def chinese_remainder_theorem(a: int, n: int, P: int, Q: int) -> int:
    M = P * Q
    m1 = Q
    m2 = P
    c1 = pow_mod(a, n % (P - 1), P)
    c2 = pow_mod(a, n % (Q - 1), Q)
    _, y1, y2 = extended_euclidean(m1, m2)
    return (c1 * m1 * y1 + c2 * m2 * y2) % M


def miller_rabin(n: int) -> bool:
    if n % 2 == 0:
        return False

    d = n - 1
    S = 0
    while d % 2 == 0:
        d >>= 1
        S += 1

    # round 1. a^d = 1 mod n
    res = pow_mod(2, d, n)
    if res == 1:
        return True

    # round 2. a^(2^r * d) = -1 mod n
    for r in range(S):
        if res == n - 1:
            return True
        res = (res * res) % n
    return False


def generate_random_prime(bits: int = 512) -> int:
    while True:
        n = random.getrandbits(bits)
        n |= 1 << bits - 1
        n |= 1
        if miller_rabin(n):
            return n


class PrivateKey:
    def __init__(self, d: int, N: int, P: int, Q: int):
        self.d = d
        self.N = N
        self.P = P
        self.Q = Q

    def __str__(self):
        return f"PrivateKey(d={self.d}, N={self.N}, P={self.P}, Q={self.Q})"


class PublicKey:
    def __init__(self, e: int, N: int):
        self.e = e
        self.N = N

    def __str__(self):
        return f"PublicKey(e={self.e}, N={self.N})"


def generate_keypair(bits: int = 1024) -> tuple[PublicKey, PrivateKey]:
    P = generate_random_prime(bits // 2)
    Q = generate_random_prime(bits // 2)
    while P == Q:
        Q = generate_random_prime(bits // 2)
    N = P * Q
    PHI = (P - 1) * (Q - 1)
    e = random.randint(3, PHI - 1)
    while extended_euclidean(e, PHI)[0] != 1:
        e = random.randint(3, PHI - 1)

    d = extended_euclidean(PHI, e)[2]
    d = d % PHI

    PK = PublicKey(e, N)
    SK = PrivateKey(d, N, P, Q)
    return PK, SK


def encrypt(message: int, public_key: PublicKey) -> int:
    return pow_mod(message, public_key.e, public_key.N)


def decrypt(ciphertext: int, private_key: PrivateKey) -> int:
    return chinese_remainder_theorem(
        ciphertext, private_key.d, private_key.P, private_key.Q
    )


def sign(message: int, private_key: PrivateKey) -> int:
    return chinese_remainder_theorem(
        message, private_key.d, private_key.P, private_key.Q
    )


def verify(signature: int, message: int, public_key: PublicKey) -> bool:
    return pow_mod(signature, public_key.e, public_key.N) == message


def main():
    RSA_bits = int(input("RSA méret: "))
    PK, SK = generate_keypair(RSA_bits)
    print("Nyilvános kulcs:", PK)
    print("Privát Kulcs:", SK)

    print("\nTitkosítás:")
    message = int(input("Üzenet: "))
    while message < 0 or message >= PK.N:
        print("Az üzenetnek 0 és N között kell lennie.")
        message = int(input("Üzenet: "))

    ciphertext = encrypt(message, PK)
    print("Titkosított üzenet:", ciphertext)

    decrypted_message = decrypt(ciphertext, SK)
    print("Visszafejtett üzenet:", decrypted_message)
    assert decrypted_message == message

    print("\nAláírás:")
    signature = sign(message, SK)
    print("Üzenet aláírása:", signature)

    is_valid = verify(signature, message, PK)
    print("Aláírás érvényes:", is_valid)
    assert is_valid


assert extended_euclidean(544, 119) == (17, 2, -9)
assert extended_euclidean(280, 3) == (1, 1, -93)
assert extended_euclidean(13, 7) == (1, -1, 2)
assert pow_mod(129, 97, 171) == 108
assert pow_mod(6, 73, 100) == 16
assert pow_mod(1924, 690, 50) == 26
assert chinese_remainder_theorem(1727, 727, 83, 67) == 52
assert chinese_remainder_theorem(47, 166379, 463, 547) == 131768
assert miller_rabin(561) is False
assert miller_rabin(1105) is False
assert miller_rabin(13) is True
assert miller_rabin(17) is True
assert miller_rabin(10008541) is True
PK = PublicKey(e=13903, N=31553)
SK = PrivateKey(d=8899, N=31553, P=139, Q=227)
assert encrypt(69, PK) == 17742
assert decrypt(17742, SK) == 69
assert sign(69, SK) == 23217
assert verify(23217, 69, PK) is True

if __name__ == "__main__":
    main()
