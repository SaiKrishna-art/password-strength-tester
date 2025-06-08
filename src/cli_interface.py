from password_analyzer import PasswordAnalyzer
from password_generator import generate_strong_password
from report_saver import save_report

def main():
    print("--Password Strength Analyzer--")
    password = input("Enter password to analyze: ")
    analyzer = PasswordAnalyzer(password)
    result = analyzer.analyze()


    print("\nRESULTS:")
    print(f"Password: {result['masked_password']}")
    print(f"Entropy: {result['entropy']} bits")
    print(f"Breach occurrences: {result['breach_count'] if result['breach_count'] >=0 else 'API Error'}")
    print(f"Strength: {result['strength'].upper()}")
    print(f"Recommendation: {result['recommendation']}")

    print(f"\n\n Strength Meter: [{'=' * int(result['strength_score']//10)}{' ' * (10 - int(result['strength_score']//10))}] {result['strength_score']}%")

    print("\n Generate a strong password? (y/n) ")
    if input().lower() == 'y':
        new_pass = generate_strong_password()
        print(f"\n Suggested password: {new_pass}")

        print("Analyze this password? (y/n) ")
        if input().lower() == 'y':
            analyzer = PasswordAnalyzer(new_pass)
            gen_result = analyzer.analyze()
            print(f"\n Strength: {gen_result['strength'].upper()}")
            print(f"Entropy: {gen_result['entropy']} bits")

    print("\n Save report (y/n) ")
    if input().lower() == 'y':
        filename = save_report(result)
        print(f"Report saved to {filename}")

if __name__ == "__main__":
    main()