from ida_kernwin import Choose, Form
import ida_kernwin
import ida_idaapi
import ida_hexrays

from utils import get_code, get_global_data, get_bytes, execute_code, main_thread
from google import genai
from google.genai import types
from dotenv import load_dotenv
import os
import threading


models = [
    "gemini-2.5-pro-preview-06-05",
    "gemini-2.5-pro-preview-05-06",
    "gemini-2.5-flash-preview-04-17",
    "gemini-2.5-flash-preview-05-20",
    "gemini-2.0-flash",
    "gemini-2.0-flash-lite"
]


class StartForm(Form):
    def __init__(self):
        Form.__init__(self, r"""STARTITEM {id:model}
BUTTON YES* Start
BUTTON CANCEL Cancel
Auto-analysis

<:{model}>
<#Additional info#Prompt :{prompt}>
<Remote address :{address}> | <Remote port :{port}>

<##Options##Do not ask before executing code:{code_execution}>{checkboxes}>
""",    {
            'prompt': Form.StringInput(),
            'address': Form.StringInput(),
            'port': Form.StringInput(),
            'model' : Form.EmbeddedChooserControl(ModelChooser("Model", [[i] for i in models], 0)),
            'checkboxes': Form.ChkGroupControl(("code_execution", )),
        })


class Analysis(ida_kernwin.action_handler_t):
    def __init__(self):
        ida_kernwin.action_handler_t.__init__(self)
        self.client = genai.Client(api_key=os.getenv("GEMINI_KEY"))
        self.running = False

    def worker(self, prompt: str = "", address: str = "", port: str = ""):
            self.running = True
            try:
                response = self.chat.send_message(
                    get_code("main") 
                    + (f"\n\n{prompt}" if prompt else "")
                    + (f"\n\nRemote address: {address}\nRemote port: {port}" if address and port else "")
                )
                ida_kernwin.msg(f"Response: {response.text}\n")
                if response.prompt_feedback:
                    ida_kernwin.msg(f"Feedback: {response.prompt_feedback}\n")
                for _ in range(3):
                    reply = main_thread(ida_kernwin.ask_text)(0, "", f"{response.text}\n\nResponse:")
                    if not reply:
                        break
                    response = self.chat.send_message(reply)
                    ida_kernwin.msg(f"Response: {response.text}\n")
                    if response.prompt_feedback:
                        ida_kernwin.msg(f"Feedback: {response.prompt_feedback}\n")
                ida_kernwin.msg("Thread ended\n")
            finally:
                self.running = False

    def activate(self, ctx):
        if self.running:
            ida_kernwin.msg("Already running\n")
            return 0

        form = StartForm()
        try:
            form.Compile()
            if form.Execute() != ida_kernwin.ASKBTN_YES:
                return 0
            
            model = models[(form.model.selection or [0])[0]]
            
            ida_kernwin.msg("Starting analysis\n")

            self.chat = self.client.chats.create(
                model=model,
                config=types.GenerateContentConfig(
                    tools=[get_code, get_global_data, get_bytes, execute_code(not form.code_execution.checked)], # types.Tool(code_execution=types.ToolCodeExecution)
                    system_instruction="Act as a reverse engineer and pwn expert participating in a CTF. You will receive the decompiled code of a C main function of a CTF challenge, if you need the code of other functions or the data of global variables call the relevant function. Your goal is to find the hidden flag. If needed write a python script and execute it using execute_code (you can use z3, angr and all common rev libraries). A challenge can have a remote address and port, use pwntools to interact with it. When calling functions do not include a message as it will not be processed."
                ),
            )
            
            threading.Thread(target=self.worker, args=(form.prompt.value, form.address.value, form.port.value)).start()
            ida_kernwin.msg("Thread started\n")
        finally:
            form.Free()
        return 0

    def update(self, ctx):
        return ida_kernwin.AST_DISABLE_FOR_WIDGET if self.running else ida_kernwin.AST_ENABLE_FOR_WIDGET


class ModelChooser(Choose):
    def __init__(self, title, models: list[str], flags = 0):
        Choose.__init__(self,
                        title,
                        [ ["Model", Choose.CHCOL_PLAIN] ],
                        flags=flags,
                        embedded=True, width=30, height=len(models))
        self.items = models
        self.icon = 36

    def OnGetLine(self, n):
        return self.items[n]

    def OnGetSize(self):
        return len(self.items)


class Gemmer(ida_idaapi.plugin_t):
    flags = ida_idaapi.PLUGIN_HIDE
    help = ""
    comment = "This plugin performs an analysis of the code with AI"
    wanted_name = "Gemmer"
    wanted_hotkey = ""

    def init(self):
        if ida_hexrays.init_hexrays_plugin():
            ida_kernwin.msg("[Gemmer] Starting\n")
            load_dotenv(dotenv_path=os.path.join(os.path.dirname(__file__), ".env"))

            if ida_kernwin.register_action(ida_kernwin.action_desc_t(
                "gemmer:start",
                "Start auto-analysis",
                Analysis(),
                "Shift+G"
            )):
                print("Action registered. Attaching to menu.")

                if ida_kernwin.attach_action_to_toolbar("AnalysisToolBar", "gemmer:start"):
                    print("Attached to toolbar.")
                else:
                    print("Failed attaching to toolbar.")

            return ida_idaapi.PLUGIN_KEEP

def PLUGIN_ENTRY():
    return Gemmer()