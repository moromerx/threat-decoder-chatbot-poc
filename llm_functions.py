import base64
import json
import os
from dotenv import load_dotenv
import requests
import streamlit as st

load_dotenv()

def decode_base64(b64_encoded_string: str):
    """Decodes a Base 64 encoded string."""
    try:
        decoded_bytes = base64.b64decode(b64_encoded_string)
        decoded_str = decoded_bytes.decode('utf-8', 'ignore')
        return decoded_str
    except Exception as e:
        return f"Error decoding Base64: {str(e)}"

def decode_base32(b32_encoded_string: str):
    """Decodes a Base 32 encoded string."""
    try:
        decoded_bytes = base64.b32decode(b32_encoded_string)
        decoded_str = decoded_bytes.decode('utf-8', 'ignore')
        return decoded_str
    except Exception as e:
        return f"Error decoding Base32: {str(e)}"

def decode_url(url_encoded_string: str) -> str:
    """Decodes a URL encoded string."""
    try:
        decoded_string = urllib.parse.unquote(url_encoded_string)
        return decoded_string
    except Exception as e:
        return f"Error decoding URL string: {e}"

def virustotal_info_with_hash(hash):
    """Fetches a VirusTotal report for the given file hash."""
    try:
        url = f"https://www.virustotal.com/api/v3/files/{hash}"
        headers = {
            "accept": "application/json",
            "x-apikey": os.getenv("VIRUSTOTAL_API_KEY"),
        }
        response = requests.get(url, headers=headers)
        if response.status_code == 200:
            data = response.json()
            result = {
                "file_hash": hash,
                "file_name": data.get("data", {}).get("attributes", {}).get("meaningful_name", "N/A"),
                "last_analysis_stats": data.get("data", {}).get("attributes", {}).get("last_analysis_stats", {}),
                "reputation": data.get("data", {}).get("attributes", {}).get("reputation", "N/A"),
                "last_analysis_date": data.get("data", {}).get("attributes", {}).get("last_analysis_date", "N/A")
            }
            return json.dumps(result)
    except Exception as e:
        return f"Failed to fetch data for hash: {file_hash}, status code: {response.status_code}"

def virustotal_info_with_ip(ip):
    """Fetches a VirusTotal report for the given IP address."""
    try:
        url = f"https://www.virustotal.com/api/v3/ip_addresses/{ip}"
        headers = {
            "accept": "application/json",
            "x-apikey": os.getenv("VIRUSTOTAL_API_KEY"),
        }
        response = requests.get(url, headers=headers)
        if response.status_code == 200:
            data = response.json()
            result = {
                "ip_address": ip,
                "last_analysis_stats": data.get("data", {}).get("attributes", {}).get("last_analysis_stats", {}),
                "reputation": data.get("data", {}).get("attributes", {}).get("reputation", "N/A"),
                "last_analysis_date": data.get("data", {}).get("attributes", {}).get("last_analysis_date", "N/A")
            }
            return json.dumps(result)
    except Exception as e:
        return f"Failed to fetch data for IP: {ip}, status code: {response.status_code}"

def new_chat():
    st.session_state.messages = []
    st.session_state.chat_history = []