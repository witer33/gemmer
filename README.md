# Gemmer
Useless IDA Pro plugin because yes
## Install
```bash
# replace ida-pro-9.1 with your ida directory
git clone https://github.com/witer33/gemmer ~/ida-pro-9.1/plugins/gemmer
pip3 install -r ~/ida-pro-9.1/plugins/gemmer/requirements.txt
```
### I recommend having at least z3, angr and numpy installed as Gemini may use them.
## Configuration
```bash
# replace ida-pro-9.1 with your ida directory
cd ~/ida-pro-9.1/plugins/gemmer
cp .env.example .env
nano .env # add your Gemini API key here.
```