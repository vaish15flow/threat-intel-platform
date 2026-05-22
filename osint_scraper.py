import requests
from bs4 import BeautifulSoup

# This is a sample URL to test if your internet/requests work
url = "https://www.google.com" 

def test_connection():
    response = requests.get(url)
    if response.status_code == 200:
        print("✅ Connection Successful! You are ready to scrape.")
    else:
        print("❌ Connection failed.")

if __name__ == "__main__":
    test_connection()