tools = [
    {
        "type": "function",
        "function": {
            "name": "decode_base64",
            "strict": True,
            "description": "Decode a Base64 encoded string. This tool should be used when you need to convert a Base64 encoded string back to its original form.",
            "parameters": {
                "type": "object",
                "properties": {
                    "b64_encoded_string": {
                        "type": "string",
                        "description": "The Base64 encoded string to decode."
                    }
                },
                "required": ["b64_encoded_string"],
                "additionalProperties": False,
            }
        }
    },
    {
        "type": "function",
        "function": {
            "name": "decode_base32",
            "strict": True,
            "description": "Decode a Base32 encoded string. This tool should be used when you need to convert a Base32 encoded string back to its original form.",
            "parameters": {
                "type": "object",
                "properties": {
                    "b32_encoded_string": {
                        "type": "string",
                        "description": "The Base32 encoded string to decode."
                    }
                },
                "required": ["b32_encoded_string"],
                "additionalProperties": False,
            }
        }
    },
    {
        "type": "function",
        "function": {
            "name": "decode_url",
            "strict": True,
            "description": "Decode a URL encoded string. This tool should be used when you need to convert a URL encoded string back to its original form.",
            "parameters": {
                "type": "object",
                "properties": {
                    "url_encoded_string": {
                        "type": "string",
                        "description": "The URL encoded string to decode."
                    }
                },
                "required": ["url_encoded_string"],
                "additionalProperties": False
            }
        }
    },
    {
        "type": "function",
        "function": {
            "name": "virustotal_info_with_hash",
            "strict": True,
            "description": "Get information from VirusTotal with a specific hash",
            "parameters": {
                "type": "object",
                "properties": {
                    "hash": {
                        "type": "string",
                        "description": "The hash to search for in VirusTotal. It should be a 64-character hexadecimal string e.g. cb1553a3c88817e4cc774a5a93f9158f6785bd3815447d04b6c3f4c2c4b21ed7",
                    }
                },
                "required": ["hash"],
                "additionalProperties": False
            }
        }
    },
    {
        "type": "function",
        "function": {
            "name": "virustotal_info_with_ip",
            "strict": True,
            "description": "Get information from VirusTotal with a specific IP",
            "parameters": {
                "type": "object",
                "properties": {
                    "ip": {
                        "type": "string",
                        "description": "The IP to search for in VirusTotal. It should be a valid IPv4 or IPv6 address e.g. 192.168.1.1 or 2001:0db8:85a3:0000:0000:8a2e:0370:7334",
                    }
                },
                "required": ["ip"],
                "additionalProperties": False
            }
        }
    }
]
