import os
from dotenv import load_dotenv
import json
from openai import OpenAI
import streamlit as st
import llm.llm_functions as llm_functions
import llm.llm_tools as llm_tools

# Load environment variables
load_dotenv()
deployment_name = "gpt-4o"

# Check for OpenAI API key
api_key = os.getenv("OPENAI_API_KEY")
if not api_key:
    st.error("🚨 OpenAI API key not found. Please set the environment variable OPENAI_API_KEY and restart the app.")
    st.stop()

client = OpenAI(
    api_key=api_key,
    base_url=os.getenv("OPENAI_BASE_URL"),  # or leave as None if you’re using the default endpoint
)

def generate_text_with_conversation(messages):
    """
    Generates text based on the conversation messages using the OpenAI chat completions API.

    Parameters:
    messages (list): A list of message objects representing the conversation history.

    Returns:
    dict: The API response containing the message content and tool calls.
    """
    try:
        response = client.chat.completions.create(
            model=deployment_name,
            messages=messages,
            tools=llm_tools.tools,
            tool_choice="auto"
        )
        return response.choices[0].message
    except Exception as e:
        st.error(f"Error in generating text with conversation: {e}")
        return None

available_tools = {
    "decode_base64": llm_functions.decode_base64,
    "decode_base32": llm_functions.decode_base32,
    "decode_url": llm_functions.decode_url,
    "virustotal_info_with_hash": llm_functions.virustotal_info_with_hash,
    "virustotal_info_with_ip": llm_functions.virustotal_info_with_ip,
}

def generate_text_with_conversation(messages):
    """
    Generates text based on the conversation messages using the OpenAI chat completions API.

    Parameters:
    messages (list): A list of message objects representing the conversation history.

    Returns:
    dict: The API response containing the message content and tool calls.
    """
    try:
        response = client.chat.completions.create(
            model=deployment_name,
            messages=messages,
            tools=llm_tools.tools,
            tool_choice="auto"
        )
        return response.choices[0].message
    except Exception as e:
        st.error(f"Error in generating text with conversation: {e}")
        return None

available_tools = {
    "decode_base64": llm_functions.decode_base64,
    "decode_base32": llm_functions.decode_base32,
    "decode_url": llm_functions.decode_url,
    "virustotal_info_with_hash": llm_functions.virustotal_info_with_hash,
    "virustotal_info_with_ip": llm_functions.virustotal_info_with_ip,
}


BASE_SYSTEM_PROMPT = """ 
You are OpenAI, an AI assistant powered by the GPT-4 model, specialized in SOC related tasks such decoding and fetching data from virus total using your available tools. 
With access to a range of tools for decoding formats such as Base64, and more, you can automatically determine the encoding method used and apply the appropriate tools to decode the text. Whether the input is encoded multiple times or involves a combination of methods, you are equipped to analyze and decode it step by step until the original text is revealed.
When done with the decoding process, always ask the user if they want to decode anything else or ask anything.

With access to tools for fetching data from VirusTotal, you can automatically gather detailed information about files, URLs, IP addresses, and more using specific hashes or IPs. Whether the input is a file hash or an IP address, you are equipped to retrieve relevant data such as threat analysis, malware detection, and reputation scores step by step. You can analyze and cross-reference this information to provide comprehensive insights. 
Once the information is retrieved, you can ask the user if they want to analyze another hash or IP, or if they have any other questions.

Available tools:
{available_tools}

Tool Usage Guidelines:
- Always use the most appropriate tool for the task at hand.
- Provide detailed and clear instructions when using tools.
- After making changes, always review the output to ensure accuracy and alignment with intentions.

Error Handling and Recovery:
- If a tool operation fails, carefully analyze the error message and attempt to resolve the issue.

When using tools:
1. Carefully consider if a tool is necessary before using it.
2. Ensure all required parameters are provided and valid.
3. Handle both successful results and errors gracefully.
4. Provide clear explanations of tool usage and results to the user.

Remember, you are an AI assistant, and your primary goal is to help the user accomplish their tasks effectively and efficiently while maintaining the integrity and security of their development environment.
"""

# Streamlit UI
st.title("Threat Decoder")

st.button("New Chat", on_click=llm_functions.new_chat)

if "messages" not in st.session_state:
    st.session_state.messages = [
        {"role": "system", "content": BASE_SYSTEM_PROMPT},
    ]

if 'chat_history' not in st.session_state:
    st.session_state.chat_history = []

# Display chat messages from history on app rerun
for message in st.session_state.chat_history:
    if isinstance(message, dict):
        role = message.get("role", "")
        content = message.get("content", "")
    elif isinstance(message, str):
        role = "assistant"
        content = message
    else:
        role = getattr(message, "role", "assistant")
        content = getattr(message, "content", "")
    
    with st.chat_message(role):
        st.markdown(content)

# React to user input
if prompt := st.chat_input("How can I help?"):
    # Display user message in chat message container
    st.chat_message("user").markdown(prompt)
    # Add user message to chat history
    st.session_state.messages.append({"role": "user", "content": prompt})
    st.session_state.chat_history.append({"role": "user", "content": prompt})

    with st.chat_message("assistant"):
        message_placeholder = st.empty()
        turn_count = 0
        max_turns = 10
        full_response = ""
        tool_response = ""
        tools_used = [] 

        while turn_count < max_turns:
            turn_count += 1
            response = generate_text_with_conversation(st.session_state.messages)
            
            if response is None:
                # If we returned None due to an error, break out
                error_txt = "\n\nUnable to continue the conversation due to error."
                message_placeholder.markdown(error_txt)
                st.session_state.chat_history.append({"role": "assistant", "content": error_txt})
                st.session_state.messages.append({"role": "assistant", "content": error_txt})
                break

            # Append the assistant's message
            st.session_state.messages.append(response)
            
            tool_calls = response.tool_calls

            if tool_calls:
                with st.spinner("Processing"):
                    for tool_call in tool_calls:
                        try:
                            tool_name = tool_call.function.name
                            tool_id = tool_call.id
                            arguments = json.loads(tool_call.function.arguments)

                            # Call the function
                            action_function = available_tools.get(tool_name)
                            if action_function:
                                result = action_function(**arguments)
                                st.session_state.messages.append({
                                    "role": "tool",
                                    "name": tool_name,
                                    "content": result,
                                    "tool_call_id": tool_id,
                                })

                                tools_used.append(tool_name)  # Collect tool names
                                continue
                            else:
                                raise ValueError(f"No such tool: {tool_name}")
                            
                        except Exception as tool_error:
                            # Handle tool-specific errors
                            error_msg = f"Error executing tool {tool_name}: {tool_error}"
                            st.error("An issue occurred while processing your request. Please try again.")
                            st.session_state.messages.append({"role": "assistant", "content": error_msg})
                            break

                    if tools_used:
                        tools_used_str = ", ".join(tools_used)
                        tool_response = f"🛠️ Tools Used: {tools_used_str}\n\n"
                        continue
            else:
                full_response += tool_response
                full_response += response.content
                message_placeholder.markdown(full_response)
                st.session_state.chat_history.append({"role": "assistant", "content": full_response})
                break

        if turn_count >= max_turns:
            response = "\n\nMaximum number of turns reached."
            message_placeholder.markdown(response)
            st.session_state.chat_history.append({"role": "assistant", "content": response})
            st.session_state.messages.append({"role": "assistant", "content": response})
