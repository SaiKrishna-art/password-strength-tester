import math
import hashlib
import requests
from typing import Union

class PasswordAnalyzer:
    """Analyzes password strength using entropy calculation and breach database checks through HIBP API"""
    def __init__(self, password: str):
        self.password = password
        self.common_passwords = ["password", "123456", "qwerty", "letmein"]
    def calculate_entropy(self) -> float:
        """Calculate Shannon entropy in bits for password strength analysis
        Entropy measures password unpredictably based on:
        -Character diversity (lowercase, uppercase, digits, symbols)
        -Password length
        Formula: H = L*log2(N)
        where:
            L = password length
            N = size of character pool
        Returns:
            float: Entropy value in bits (rounded to 2 decimals)
        """
        char_pool = 0
        if any(c.islower() for c in self.password):
            char_pool += 26
        if any(c.isupper() for c in self.password):
            char_pool += 26
        if any(c.isdigit() for c in self.password):
            char_pool += 10
        if any(not c.isalnum() for c in self.password):
            char_pool += 32

        if len(self.password) == 0:
            return 0.0

        entropy = len(self.password) * math.log2(char_pool) if char_pool > 0 else 0
        return round(entropy, 2)
    def check_hibp(self) -> int:
        """Check password against Have I Been Pwned database"""
        sha1_password = hashlib.sha1(self.password.encode('utf-8')).hexdigest().upper()
        prefix, suffix = sha1_password[:5], sha1_password[5:]
        try:
            response = requests.get(
                f"https://api.pwnedpasswords.com/range/{prefix}",
                headers={"Add-Padding" : "true"},
                timeout = 3
            )
            for line in response.text.splitlines():
                if line.startswith(suffix):
                    return int(line.split(':')[1])
        except requests.exceptions.RequestException:
            return -1
        return 0
    def analyze(self) -> dict[str, Union[float, int, str]]:
        """Run full analysis and return results"""
        entropy = self.calculate_entropy()
        breaches = self.check_hibp()
        if breaches < 0:
            strength = "error"
            recommendation = "API Error: Couldn't check breaches"
        elif entropy < 28 or breaches > 0:
            strength = "critical"
            recommendation = "CRITICAL: Change immediately!"
        elif entropy < 40:
            strength = "weak"
            recommendation = "WEAK: Add symbols/numbers"
        elif entropy < 60:
            strength = "moderate"
            recommendation = "MODERATE: Increase the password length"
        else:
            strength = "strong"
            recommendation = "STRONG: Good password"
        strength_score = min(entropy/80*100, 100)
        return {
            "masked_password": self.password[:2] + "*" * (len(self.password) - 2),
            "entropy": entropy,
            "breach_count": breaches,
            "strength": strength,
            "recommendation": recommendation,
            "strength_score": round(strength_score, 1)
        }
    def check_policies(self) -> dict:
        """Check password against commin security policies
        Returns dictionary with policy compliance status"""
        return{
            "length": len(self.password) >= 8,
            "uppercase": any(c.isupper() for c in self.password),
            "lowercase": any(c.islower() for c in self.password),
            "digit": any(c.isdigit() for c in self.password),
            "special": any(c.isalnum() for c in self.password),
            "not_common": self.password.lower() not in self.common_passwords
        }

if __name__ == "__main__":
    test_password = "SaiKrishna@0808"
    analyzer = PasswordAnalyzer(test_password)
    result = analyzer.analyze()

    print(f"\nPassword Analysis: '{test_password}'")
    print(f"- Entropy: {result['entropy']} bits")
    print(f"- Breach occurrences: {result['breach_count'] if result['breach_count'] >= 0 else 'API Error'}")
    print(f"- Recommendation: {result['recommendation']}")