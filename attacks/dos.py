import requests
import threading
import time

def login():
    """Login to get session"""
    session = requests.Session()
    url = 'http://127.0.0.1:5000/'
    data = {'username': 'admin', 'password': 'admin123'}
    response = session.post(url, data=data, allow_redirects=False)  # Don't follow redirect
    print(f"Login response: {response.status_code}")
    return session if response.status_code == 302 else None

def send_request(session):
    url = 'http://127.0.0.1:5000/upload'
    files = {'file': ('test.txt', 'test content')}
    try:
        response = session.post(url, files=files)
        print(f"Request: {response.status_code}")
    except Exception as e:
        print(f"Error: {e}")

def simulate_dos():
    """
    Simulate DoS attack by sending rapid requests.
    """
    session = login()
    if not session:
        print("Failed to login")
        return
    threads = []
    for i in range(15):  # Many requests
        t = threading.Thread(target=send_request, args=(session,))
        threads.append(t)
        t.start()
        time.sleep(0.01)  # Slight stagger

    for t in threads:
        t.join()

if __name__ == '__main__':
    simulate_dos()
