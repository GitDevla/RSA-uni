import secrets

MESSAGE_ENCODING_FACTOR = 100

#region Utils
def extended_euclidean(dividend: int, divisor: int) -> tuple[int, int, int]:
    previous_x, current_x = 1, 0
    previous_y, current_y = 0, 1

    sign = 1
    while divisor != 0:
        quotient, remainder = dividend // divisor, dividend % divisor
        dividend, divisor = divisor, remainder
        previous_x, current_x = current_x, quotient * current_x + previous_x
        previous_y, current_y = current_y, quotient * current_y + previous_y
        sign = -sign

    gcd = dividend
    x = sign * previous_x
    y = -sign * previous_y
    return gcd, x, y


def pow_mod(base: int, exponent: int, modulus: int) -> int:
    result = 1
    base %= modulus
    while exponent > 0:
        if exponent % 2 == 1:
            result = (result * base) % modulus
        base = (base * base) % modulus
        exponent >>= 1
    return result


def inverse_mod(value: int, modulus: int) -> int:
    gcd, inverse, _ = extended_euclidean(value % modulus, modulus)
    if gcd != 1:
        raise ValueError(f"{value} nem invertálható modulo {modulus}")
    return inverse % modulus


def square_root_mod(value: int, prime: int) -> int | None:
    assert prime % 4 == 3
    root = pow_mod(value, (prime + 1) // 4, prime)
    if root * root % prime != value % prime:
        return None
    return root
#endregion

#region ECC
class Curve:
    def __init__(
        self, a: int, b: int, prime: int, generator: tuple[int, int], order: int
    ):
        self.a = a % prime
        self.b = b % prime
        self.prime = prime
        self.generator = Point(generator[0], generator[1], self)
        self.order = order

    def contains(self, x: int, y: int) -> bool:
        return (y * y - (x**3 + self.a * x + self.b)) % self.prime == 0

    def infinity(self) -> "Point":
        return Point(None, None, self)

    def __str__(self):
        return f"y^2 = x^3 + {self.a}x + {self.b} (mod {self.prime})"


class Point:
    def __init__(self, x: int | None, y: int | None, curve: Curve):
        self.x = x
        self.y = y
        self.curve = curve

    def is_infinity(self) -> bool:
        return self.x is None

    def __eq__(self, other: "Point") -> bool:
        return (self.x, self.y) == (other.x, other.y)

    def __neg__(self) -> "Point":
        if self.is_infinity():
            return self
        return Point(self.x, -self.y % self.curve.prime, self.curve)

    def __add__(self, other: "Point") -> "Point":
        if self.is_infinity():
            return other
        if other.is_infinity():
            return self
        if self == -other:
            return self.curve.infinity()

        assert self.x is not None and other.x is not None and self.y is not None and other.y is not None

        prime = self.curve.prime
        if self == other:
            slope = (3 * self.x**2 + self.curve.a) * inverse_mod(2 * self.y, prime)
        else:
            slope = (other.y - self.y) * inverse_mod(other.x - self.x, prime)

        x = (slope**2 - self.x - other.x) % prime
        y = (slope * (self.x - x) - self.y) % prime
        return Point(x, y, self.curve)

    def __sub__(self, other: "Point") -> "Point":
        return self + -other

    def __rmul__(self, scalar: int) -> "Point":
        result = self.curve.infinity()
        doubled_point = self
        while scalar > 0:
            if scalar % 2 == 1:
                result = result + doubled_point
            doubled_point = doubled_point + doubled_point
            scalar >>= 1
        return result

    def __str__(self):
        if self.is_infinity():
            return "O"
        return f"({self.x}, {self.y})"

    __repr__ = __str__


SECP256K1 = Curve(
    a=0,
    b=7,
    prime=0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEFFFFFC2F,
    generator=(
        0x79BE667EF9DCBBAC55A06295CE870B07029BFCDB2DCE28D959F2815B16F81798,
        0x483ADA7726A3C4655DA4FBFC0E1108A8FD17B448A68554199C47D08FFB10D4B8,
    ),
    order=0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141,
)

DUMMY_CURVE = Curve(a=0, b=5, prime=1000003, generator=(1, 413233), order=999007)

ACTIVE_CURVE = DUMMY_CURVE


class PrivateKey:
    def __init__(self, scalar: int, curve: Curve):
        self.scalar = scalar
        self.curve = curve

    def __str__(self):
        return f"PrivateKey(scalar={self.scalar})"


class PublicKey:
    def __init__(self, point: Point):
        self.point = point
        self.curve = point.curve

    def __str__(self):
        return f"PublicKey(point={self.point})"

#endregion


def generate_random_scalar(curve: Curve) -> int:
    return secrets.randbelow(curve.order - 3) + 2


def generate_keypair(curve: Curve) -> tuple[PublicKey, PrivateKey]:
    scalar = generate_random_scalar(curve)
    point = scalar * curve.generator
    return PublicKey(point), PrivateKey(scalar, curve)


def shared_secret(private_key: PrivateKey, public_key: PublicKey) -> Point:
    return private_key.scalar * public_key.point


def compute_message_limit(curve: Curve) -> int:
    return curve.prime // MESSAGE_ENCODING_FACTOR


def encode_message(message: int, curve: Curve) -> Point:
    for offset in range(MESSAGE_ENCODING_FACTOR):
        x = message * MESSAGE_ENCODING_FACTOR + offset
        y = square_root_mod(x**3 + curve.a * x + curve.b, curve.prime)
        if y is not None:
            return Point(x, y, curve)
    raise ValueError(f"A(z) {message} üzenet nem kódolható pontként.")


def decode_message(message_point: Point) -> int:
    assert message_point.x is not None
    return message_point.x // MESSAGE_ENCODING_FACTOR


def encrypt_point(
    message_point: Point, public_key: PublicKey, nonce: int
) -> tuple[Point, Point]:
    nonce_point = nonce * public_key.curve.generator
    masked_point = message_point + nonce * public_key.point
    return nonce_point, masked_point


def decrypt_point(ciphertext: tuple[Point, Point], private_key: PrivateKey) -> Point:
    nonce_point, masked_point = ciphertext
    return masked_point - private_key.scalar * nonce_point


def encrypt(message: int, public_key: PublicKey) -> tuple[Point, Point]:
    message_point = encode_message(message, public_key.curve)
    nonce = generate_random_scalar(public_key.curve)
    return encrypt_point(message_point, public_key, nonce)


def decrypt(ciphertext: tuple[Point, Point], private_key: PrivateKey) -> int:
    return decode_message(decrypt_point(ciphertext, private_key))


def sign(message: int, private_key: PrivateKey) -> tuple[int, int]:
    curve = private_key.curve
    order = curve.order
    while True:
        nonce = generate_random_scalar(curve)
        nonce_point = nonce * curve.generator
        assert nonce_point.x is not None
        nonce_x = nonce_point.x % order
        signed_value = message + private_key.scalar * nonce_x
        proof = inverse_mod(nonce, order) * signed_value % order
        if nonce_x != 0 and proof != 0:
            return nonce_x, proof


def verify(signature: tuple[int, int], message: int, public_key: PublicKey) -> bool:
    nonce_x, proof = signature
    curve = public_key.curve
    order = curve.order
    if not (0 < nonce_x < order and 0 < proof < order):
        return False

    proof_inverse = inverse_mod(proof, order)
    message_weight = message * proof_inverse % order
    key_weight = nonce_x * proof_inverse % order
    check_point = message_weight * curve.generator + key_weight * public_key.point
    assert check_point.x is not None
    return not check_point.is_infinity() and check_point.x % order == nonce_x


def main():
    curve = ACTIVE_CURVE
    print("Görbe:", curve)
    public_key, private_key = generate_keypair(curve)
    print("Nyilvános kulcs:", public_key)
    print("Privát kulcs:", private_key)

    print("\nKulcscsere (ECDH):")
    partner_public_key, partner_private_key = generate_keypair(curve)
    print("Másik fél nyilvános kulcsa:", partner_public_key)
    secret = shared_secret(private_key, partner_public_key)
    print("Közös titok:", secret)
    assert secret == shared_secret(partner_private_key, public_key)

    print("\nTitkosítás:")
    message_limit = compute_message_limit(curve)
    message = int(input("Üzenet: "))
    while message < 0 or message >= message_limit:
        print(f"Az üzenetnek 0 és {message_limit} között kell lennie.")
        message = int(input("Üzenet: "))

    print("Üzenet pontként:", encode_message(message, curve))
    ciphertext = encrypt(message, public_key)
    print("Titkosított üzenet:", ciphertext)

    decrypted_message = decrypt(ciphertext, private_key)
    print("Visszafejtett üzenet:", decrypted_message)
    assert decrypted_message == message

    print("\nAláírás:")
    signature = sign(message, private_key)
    print("Üzenet aláírása:", signature)

    is_valid = verify(signature, message, public_key)
    print("Aláírás érvényes:", is_valid)
    assert is_valid


assert extended_euclidean(544, 119) == (17, 2, -9)
assert extended_euclidean(280, 3) == (1, 1, -93)
assert pow_mod(129, 97, 171) == 108
assert inverse_mod(3, 7) == 5
assert inverse_mod(-1, 23) == 22
assert square_root_mod(4, 23) in (2, 21)
assert square_root_mod(5, 23) is None

curve_23 = Curve(a=1, b=1, prime=23, generator=(3, 10), order=28)
first_point = Point(3, 10, curve_23)
second_point = Point(9, 7, curve_23)
assert first_point + second_point == Point(17, 20, curve_23)
assert first_point + first_point == Point(7, 12, curve_23)
assert 2 * first_point == Point(7, 12, curve_23)
assert first_point - first_point == curve_23.infinity()
assert 28 * first_point == curve_23.infinity()
assert curve_23.contains(17, 20)

curve_211 = Curve(a=0, b=-4, prime=211, generator=(2, 2), order=241)
alice_public_key = PublicKey(121 * curve_211.generator)
alice_private_key = PrivateKey(121, curve_211)
bob_public_key = PublicKey(203 * curve_211.generator)
bob_private_key = PrivateKey(203, curve_211)
assert alice_public_key.point == Point(115, 48, curve_211)
assert bob_public_key.point == Point(130, 203, curve_211)
assert shared_secret(alice_private_key, bob_public_key) == Point(161, 69, curve_211)
assert shared_secret(bob_private_key, alice_public_key) == Point(161, 69, curve_211)
assert 240 * curve_211.generator == -curve_211.generator
assert verify(sign(69, alice_private_key), 69, alice_public_key) is True
assert verify(sign(69, alice_private_key), 70, alice_public_key) is False
assert verify(sign(69, alice_private_key), 69, bob_public_key) is False

curve_751 = Curve(a=-1, b=188, prime=751, generator=(0, 376), order=727)
message_point = Point(562, 201, curve_751)
bob_public_key = PublicKey(Point(201, 5, curve_751))
bob_private_key = PrivateKey(58, curve_751)
ciphertext = encrypt_point(message_point, bob_public_key, nonce=386)
nonce_point, masked_point = ciphertext
assert nonce_point == Point(676, 558, curve_751)
assert masked_point == Point(385, 328, curve_751)
assert decrypt_point(ciphertext, bob_private_key) == message_point
assert decode_message(encode_message(5, curve_751)) == 5
assert decrypt(encrypt(5, bob_public_key), bob_private_key) == 5

assert SECP256K1.generator.x is not None and SECP256K1.generator.y is not None
assert SECP256K1.contains(SECP256K1.generator.x, SECP256K1.generator.y)
assert SECP256K1.order * SECP256K1.generator == SECP256K1.infinity()
assert DUMMY_CURVE.generator.x is not None and DUMMY_CURVE.generator.y is not None
assert DUMMY_CURVE.contains(DUMMY_CURVE.generator.x, DUMMY_CURVE.generator.y)
assert DUMMY_CURVE.order * DUMMY_CURVE.generator == DUMMY_CURVE.infinity()

if __name__ == "__main__":
    main()
