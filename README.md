Threat Intelligence \& Connectivity Tester



A simple Python project that demonstrates:



MongoDB database connectivity using pymongo

Inserting sample threat intelligence data

Internet connection testing using requests

Basic web scraping setup with BeautifulSoup



This project is useful for beginners learning:



Cybersecurity scripting

Threat intelligence data handling

Python database integration

Web requests and scraping

Features

MongoDB Threat Intelligence Module

Connects to a local MongoDB instance

Creates a database named threat\_intel

Creates a collection named indicators

Inserts a sample threat indicator record

Displays inserted record ID

Internet Connectivity Tester

Sends an HTTP request to Google

Verifies internet access

Confirms readiness for web scraping

Technologies Used

Python

pymongo

requests

beautifulsoup4

MongoDB

Project Structure

project/

│

├── database\_test.py

├── scraper\_test.py

└── README.md

Installation

1\. Clone the Repository

git clone <your-repository-url>

cd <project-folder>

2\. Install Dependencies

pip install pymongo requests beautifulsoup4

3\. Install MongoDB



Download and install MongoDB Community Edition from:



MongoDB Official Website



Make sure MongoDB is running locally on:



mongodb://localhost:27017/

Running the Project

Run MongoDB Connection Test

python database\_test.py

Expected Output

🎉 Success! Connected to MongoDB seamlessly.

Inserted dummy test record with ID: <mongodb\_object\_id>

Run Internet Connection Test

python scraper\_test.py

Expected Output

✅ Connection Successful! You are ready to scrape.

Sample Threat Record

{

&#x20; "ip\_address": "1.1.1.1",

&#x20; "threat\_type": "Malware Hosting",

&#x20; "risk\_score": 0.0,

&#x20; "status": "placeholder",

&#x20; "date\_added": "2026-05-26 22:00:00"

}

