from rules import analyze_url

def main():
    url = input("Enter URL to analyze: ").strip()

    reasons = analyze_url(url)

    if reasons:
        print("\nSuspicious URL detected")
        print("Reasons:")
        for reason in reasons:
            print(f"- {reason}")
    else:
        print("\nURL appears safe")

if __name__ == "__main__":
    main()
