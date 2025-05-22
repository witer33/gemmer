from google import genai
from google.genai import types
from dotenv import load_dotenv
import os


def main():
    print("starting")
    load_dotenv()
    client = genai.Client(api_key=os.getenv("GEMINI_KEY"))

    chat = client.chats.create(
        model="gemini-2.5-flash-preview-05-20"
    )

    response = chat.send_message("ciao, questo è un test")
    print(response.prompt_feedback)
    print("Response:", response.text)


if __name__ == "__main__":
    main()