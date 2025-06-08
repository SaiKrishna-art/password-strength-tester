import unittest
from src.password_analyzer import PasswordAnalyzer


class TestPasswordAnalyzer(unittest.TestCase):
    def test_entropy_calculation(self):
        # Test empty password
        self.assertEqual(PasswordAnalyzer("").calculate_entropy(), 0.0)

        # Test simple password
        self.assertAlmostEqual(PasswordAnalyzer("abc").calculate_entropy(), 14.1, delta=0.5)

        # Test complex password
        self.assertGreater(PasswordAnalyzer("S@mpleP@ss123!").calculate_entropy(), 50.0)

    def test_breach_check(self):
        # Test known breached password
        self.assertGreater(PasswordAnalyzer("password").check_hibp(), 1000000)

        # Test strong password (should be 0 breaches)
        self.assertEqual(PasswordAnalyzer("Xk28#!9zLpQ").check_hibp(), 0)

    def test_full_analysis(self):
        # Test critical password
        result = PasswordAnalyzer("123456").analyze()
        self.assertEqual(result["strength"], "critical")

        # Test strong password
        result = PasswordAnalyzer("Jf8#nK!2pL9$").analyze()
        self.assertEqual(result["strength"], "strong")


if __name__ == "__main__":
    unittest.main()