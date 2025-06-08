import secrets
import string


def generate_strong_password(length=12):
    lowercase = string.ascii_lowercase
    uppercase = string.ascii_uppercase
    digits = string.digits
    symbols = "!@#$%^&*()_-+=<>?/"

    all_chars = lowercase+uppercase+digits+symbols

    password = [
        secrets.choice(lowercase),
        secrets.choice(uppercase),
        secrets.choice(digits),
        secrets.choice(symbols)
    ]

    password += [secrets.choice(all_chars) for _ in range(length-4)]

    secrets.SystemRandom().shuffle(password)

    return ''.join(password)
