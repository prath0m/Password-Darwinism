import requests

def query_local_ai(prompt):
    url = "http://127.0.0.1:7860/run/textgen"  # Adjust endpoint if needed
    payload = {
        "prompt": prompt,
        "max_new_tokens": 100,
        "temperature": 0.7,
        "do_sample": True
    }

    try:
        response = requests.post(url, json=payload, timeout=20)
        if response.ok:
            result = response.json()
            return result.get("results", [""])[0]
        return "No response from AI."
    except requests.exceptions.RequestException as e:
        return f"Error: {e}"
