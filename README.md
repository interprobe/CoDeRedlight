# CoDeRedlight
<img src="https://img.shields.io/badge/-Linux-black?style=for-the-badge&logo=Linux&logoColor=white"> <img src="https://img.shields.io/badge/-Python-black?style=for-the-badge&logo=python&logoColor=white"> <img src="https://img.shields.io/badge/-Terminal-black?style=for-the-badge&logo=GNU%20Bash&logoColor=white"> <img src="https://img.shields.io/badge/-GPL%203.0-black?style=for-the-badge&Color=white">
<br>A simple CDR software for disarming malicious contents contained in documents.<br>

*With CoDeRedlight you can*:
- Gather information from document files.
- Extract IoC data.
- Disarming C2 URL's and anohter malicious contents.

# Updates
- [X] Bug fixes.
- [X] Added Excel support. Now you can clear malicious contents from your file. (Effective againts embedded Equation Editor exploits)
- [X] Malicious URL finding capability is improved. Now you can clear Emotet/Heodo documents easily.

# Usage
```bash
python3 CoDeRedlight.py <target_file>
```

# Setup
```bash
pip3 install -r requirements.txt
```

# PoC
https://user-images.githubusercontent.com/108284701/200328498-9fbef911-1dec-49c5-9f03-5f7b2f7aeb51.mp4

# TODO
- [X] Add PDF and CDFv2 support.
- [X] Improve disarming capabilities.
