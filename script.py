from utils import get_code, get_global_data, get_bytes, execute_code, main_thread
import ida_auto
import ida_kernwin
import ida_name

from google import genai
from google.genai import types
from dotenv import load_dotenv
import os
import threading

class Gemmer(ida_kernwin.action_handler_t):
    def __init__(self):
        ida_kernwin.action_handler_t.__init__(self)
        self.client = genai.Client(api_key=os.getenv("GEMINI_KEY"))
        self.running = False

    def worker(self):
            try:
                response = self.chat.send_message(get_code("main"))
                ida_kernwin.msg(f"Response: {response.text}\n\nfeedback: {response.prompt_feedback}\n")
                for _ in range(3):
                    if main_thread(ida_kernwin.ask_yn)(ida_kernwin.ASKBTN_NO, f"{response.text}\n\nDo you want to retry?") != ida_kernwin.ASKBTN_YES:
                        break
                    response = self.chat.send_message("Flag is wrong, retry")
                    ida_kernwin.msg(f"Response: {response.text}\n\nfeedback: {response.prompt_feedback}\n")
                ida_kernwin.msg("Thread ended\n")
            finally:
                self.running = False

    def activate(self, ctx):
        if self.running:
            ida_kernwin.msg("Already running\n")
            return 0
        if not ida_name.get_name_ea(0, "main"):
            ida_kernwin.msg("No main function found\n")
            return 0        
        self.running = True
        
        ida_kernwin.msg("Starting analysis\n")

        self.chat = self.client.chats.create(
            model="gemini-2.5-pro-preview-05-06",
            config=types.GenerateContentConfig(
                tools=[get_code, get_global_data, get_bytes, execute_code], # types.Tool(code_execution=types.ToolCodeExecution)
                system_instruction="Act as a reverse engineer participating in a CTF. You will receive the decompiled code of a C main function of a CTF challenge, if you need the code of other functions or the data of global variables call the relevant function. Your goal is to find the hidden flag. If needed write a python script and execute it using execute_code (you can use z3, angr and all common rev libraries). When calling functions do not return text as it will not be processed."
            ),
        )
        
        threading.Thread(target=self.worker).start()
        ida_kernwin.msg("Thread started\n")
        return 0

    def update(self, ctx):
        return ida_kernwin.AST_ENABLE_FOR_WIDGET

def main():
    ida_kernwin.msg("starting\n")
    load_dotenv()
    ida_auto.auto_wait()

    if ida_kernwin.register_action(ida_kernwin.action_desc_t(
        "gemmer:start",
        "Start auto-analysis",
        Gemmer(),
        "Shift+G"
    )):
        print("Action registered. Attaching to menu.")

        if ida_kernwin.attach_action_to_toolbar("AnalysisToolBar", "gemmer:start"):
            print("Attached to toolbar.")
        else:
            print("Failed attaching to toolbar.")

if __name__ == "__main__":
    main()