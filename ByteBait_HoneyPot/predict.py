import pandas as pd
from urllib.parse import unquote
from joblib import load
import sys
import json
import re
import requests
import time  # Add this import for rate limiting
# Define a global variable for last request time
last_request_time = 0
def preprocess_input(input_value):
    """Decode URL-encoded strings, strip whitespace, and check for specific attack patterns."""
    decoded_value = unquote(input_value).strip() if input_value else input_value
    
    # Retain the XSS, directory traversal, and SQL Injection patterns detection
    attack_patterns = {
        'xss': re.compile(r"<script|javascript:|onerror=", re.IGNORECASE),
        'sql_injection': re.compile(r"(" + "|".join([
            r"\bselect\b", r"\bunion\b", r"\binsert\b", r"\bdelete\b",
            r"\bupdate\b", r"\bdrop\b", r"\bexec(\s|\()+", r"--;",
            r"\bdeclare\b", r"' OR '1'='1"
        ]) + ")", re.IGNORECASE),
        'directory_traversal': re.compile(r"\.\./|\.\.\\|%2e%2e/", re.IGNORECASE)
    }
    
    for attack_type, pattern in attack_patterns.items():
        if pattern.search(decoded_value):
            decoded_value += f" {attack_type}_pattern_detected"
            break  # Stop at the first detected pattern
    
    return decoded_value

def combine_fields_for_prediction(log_entry):
    """Extracts and combines relevant fields from the log entry for prediction."""
    combined_input = ' '.join([
        preprocess_input(log_entry.get('URL', '')),
        preprocess_input(log_entry.get('CONTENT', '')),
        preprocess_input(log_entry.get('TITLE', '')),
        preprocess_input(log_entry.get('USERNAME', '')),  # Assuming USERNAME is a relevant field
        preprocess_input(log_entry.get('PASSWORD', ''))  # Assuming PASSWORD is a relevant field
    ])
    return combined_input

def predict_log_entry(json_log_entry):
    try:
        log_entry = json.loads(json_log_entry)
        
        # Check if user-agent is python-requests, ignore prediction
        user_agent = log_entry.get('USERAGENT', '')
        if 'python-requests/2.31.0' in user_agent:
            return "Ignoring python-requests user-agent"

        combined_payload = combine_fields_for_prediction(log_entry)
        
        # Load the model
        model = load('../../attack_prediction_model.joblib')
        data = pd.DataFrame([combined_payload], columns=['Payload Data'])
        prediction = model.predict(data['Payload Data'])
        return prediction[0]
    except Exception as e:
        return f"Error in prediction: {str(e)}"



import requests
import time

# Global variables to track the request status and last request time
has_request_been_sent = False
last_request_time = 0

def send_prediction_to_webserver(attack_type, source_ip):
    global has_request_been_sent
    global last_request_time
    
    # Check if a request has already been sent
    if has_request_been_sent:
        print("A prediction request has already been sent to the webserver.")
        return

    # URL of the webserver's API endpoint
    url = 'http://127.0.0.1:4000/api/predictions'
    
    # Data to be sent in the POST request
    data = {
        'attackType': attack_type,
        'sourceIP': source_ip
    }
    
    # Sending the POST request
    try:
        response = requests.post(url, json=data)
        print("Successfully sent prediction to webserver:", response.text)
        
        # Update the flag and last_request_time only after successful request
        has_request_been_sent = True
        last_request_time = time.time()
    except requests.exceptions.RequestException as e:
        print("Error sending prediction to webserver:", e)


# Example usage (for direct script execution, replace sys.stdin.read() with actual JSON string)
if __name__ == "__main__":
    json_log_entry = sys.stdin.read()  # Or replace with actual JSON for direct testing
    prediction = predict_log_entry(json_log_entry)
    
    # Extract REMOTE_ADDR from json_log_entry
    remote_ip = json.loads(json_log_entry).get('REMOTE_ADDR', 'unknown')
    
    send_prediction_to_webserver(prediction, remote_ip)
    print(f"Predicted Attack Type: {prediction} from: {remote_ip}")
