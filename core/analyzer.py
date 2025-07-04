import os
import requests
import time
from dotenv import load_dotenv

load_dotenv()

def analyze_vulnerability(vuln_type, language="python"):
    API_KEY = os.getenv("HF_API_KEY")
    if not API_KEY:
        return "API Key is not available"
    
    headers = {
        "Authorization": f"Bearer {API_KEY}"
    }
    
    API_URL = "https://api-inference.huggingface.co/models/facebook/bart-large-cnn"
    
    prompt = f"""Summarize this vulnerability: {vuln_type}. 
    Provide a short example in {language} and mitigation steps."""
    
    payload = {
        "inputs": prompt,
        "parameters": {
            "max_length": 200,
            "min_length": 50
        },
        "options": {
            "wait_for_model": True
        }
    }

    try:
        response = requests.post(API_URL, headers=headers, json=payload, timeout=60)
        
        if response.status_code == 503:
            estimated_time = response.json().get('estimated_time', 30)
            time.sleep(estimated_time)
            return analyze_vulnerability(vuln_type, language)
            
        response.raise_for_status()
        
        output = response.json()
        
        if isinstance(output, list) and len(output) > 0:
            return output[0].get("summary_text", "No generated text available")
        return output.get("summary_text", "Bad format")
        
    except requests.exceptions.RequestException as e:
        return f"Error: {str(e)}"