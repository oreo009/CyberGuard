import requests
import time

def simulate_brute_force():
    """
    Simulate brute force attack by sending multiple failed login attempts.
    """
    url = 'http://127.0.0.1:5000/'
    for i in range(6):  # More than 5 to trigger
        data = {'username': 'wrong', 'password': 'wrong'}
        try:
            response = requests.post(url, data=data)
            print(f"Attempt {i+1}: {response.status_code}")
        except Exception as e:
            print(f"Error: {e}")
        time.sleep(0.1)  # Small delay

if __name__ == '__main__':
    simulate_brute_force()
