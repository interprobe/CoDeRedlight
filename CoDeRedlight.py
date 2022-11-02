#!/usr/bin/python3

import re
import os
import sys
import json
import binascii
import zipfile
import tempfile
import shutil

# Checking for rich
try:
    from rich import print
    from rich.table import Table
except:
    print("Error: >rich< not found.")
    sys.exit(1)

# Legends
infoS = f"[bold cyan][[bold red]*[bold cyan]][white]"
errorS = f"[bold cyan][[bold red]![bold cyan]][white]"

# File signatures
fsigs = {
    "Microsoft Word 2007+": "504b030414",
    "Microsoft Excel 2007+": "504b030414",
    "Composite Document File V2": "d0cf11e0a1b11ae1"
}

banner = """
[bold red][blink] ██████╗[/blink][white] ██████╗[bold red][blink] ██████╗[/blink][white] ███████╗[bold red][blink]██████╗ [/blink][white]███████╗██████╗ ██╗     ██╗ ██████╗ ██╗  ██╗████████╗
[bold red][blink]██╔════╝[/blink][white]██╔═══██╗[bold red][blink]██╔══██╗[/blink][white]██╔════╝[bold red][blink]██╔══██╗[/blink][white]██╔════╝██╔══██╗██║     ██║██╔════╝ ██║  ██║╚══██╔══╝
[bold red][blink]██║     [/blink][white]██║   ██║[bold red][blink]██║  ██║[/blink][white]█████╗  [bold red][blink]██████╔╝[/blink][white]█████╗  ██║  ██║██║     ██║██║  ███╗███████║   ██║   
[bold red][blink]██║     [/blink][white]██║   ██║[bold red][blink]██║  ██║[/blink][white]██╔══╝  [bold red][blink]██╔══██╗[/blink][white]██╔══╝  ██║  ██║██║     ██║██║   ██║██╔══██║   ██║   
[bold red][blink]╚██████╗[/blink][white]╚██████╔╝[bold red][blink]██████╔╝[/blink][white]███████╗[bold red][blink]██║  ██║[/blink][white]███████╗██████╔╝███████╗██║╚██████╔╝██║  ██║   ██║   
[bold red][blink] ╚═════╝ [/blink][white]╚═════╝ [bold red][blink]╚═════╝ [/blink][white]╚══════╝[bold red][blink]╚═╝  ╚═╝[/blink][white]╚══════╝╚═════╝ ╚══════╝╚═╝ ╚═════╝ ╚═╝  ╚═╝   ╚═╝   
                                                                                                   
                            By InterProbe Malware-Vulnerability Research Team
                                [bold green]@interprobe [bold blue]https://github.com/interprobe
"""

# Implementing our class
class CoDeRedlight:
    def __init__(self, filename):
        self.filename = filename

    def CheckDocType(self):
        print(f"{infoS} Checking document type...")
        # First we need to read first 24 bytes of the file
        fhandler = open(self.filename, "rb")
        fhandler.seek(0)
        fbytes = fhandler.read(24) # This one is for signature checking
        fdata = fhandler.read() # This one is for data checking
        fhandler.close()

        # Then we need to check our file signature patterns
        for sig in fsigs:
            regx = re.search(binascii.unhexlify(fsigs[sig]), fbytes)

            # If we found a match, we need to check for the strings inside the file
            if regx and sig == "Microsoft Word 2007+":
                dstr = re.findall("word/", str(fdata))
                if dstr != []:
                    print("[bold magenta]>>>[bold white]This is a [bold green]Microsoft Word 2007+ [bold white]document.\n")
                    return "Microsoft Word 2007+"

            # Checking for Excel
            if regx and sig == "Microsoft Excel 2007+":
                dstr = re.findall("xl/", str(fdata))
                if dstr != []:
                    print("[bold magenta]>>>[bold white]This is a [bold green]Microsoft Excel 2007+ [bold white]document.\n")
                    return "Microsoft Excel 2007+"

            # Checking for CDFV2
            if regx and sig == "Composite Document File V2":
                print("[bold magenta]>>>[bold white]This is a [bold green]Composite Document File V2 [bold white]document.\n")
                return "Composite Document File V2"

    def GetStructure(self):
        print(f"{infoS} Getting document structure...")

        # Table for our data
        docTable = Table(title="* Document Structure *", title_style="bold italic cyan", title_justify="center")
        docTable.add_column("[bold green]File Name", justify="center")

        # We need unzip file to see structure basically
        try:
            # If we found any of binary files, we need to extract them
            binz = []

            # Contents
            contents = []

            # Unzipping file
            document = zipfile.ZipFile(open(self.filename, "rb"))

            # Iterating over files
            for fle in document.namelist():
                if ".bin" in fle:
                    docTable.add_row(f"[bold red]{fle}")
                    binz.append(fle)
                else:
                    docTable.add_row(fle)
                    contents.append(fle)

            # Printing table and returning contents
            print(docTable)
            return [document ,binz, contents]
        except:
            print(f"{errorS} Error: [bold red]Unable to unzip file.")
            return None

    def GetInterestingURLs(self, doc_handler):
        print(f"\n{infoS} Getting interesting URLs...")
        # Tabless I see tabless everywhere!!
        urlTable = Table(title="* Interesting URLs *", title_style="bold italic cyan", title_justify="center")
        urlTable.add_column("[bold green]File", justify="center")
        urlTable.add_column("[bold green]URL", justify="center")

        # Variables
        urls = {}
        url_regex = r"http[s]?://(?:[a-zA-Z]|[0-9]|[$-_@.&+]|[!*\(\),]|(?:%[0-9a-fA-F][0-9a-fA-F]))+"

        # Getting document structure
        allfiles = doc_handler[2] + doc_handler[1]

        # First: Iterating through contents
        for fle in allfiles:
            try:
                # Read content
                content = doc_handler[0].read(fle).decode()

                # Find URLs
                linkz = re.findall(url_regex, content)

                # Append to list
                if linkz != []:
                    for lnk in linkz:
                        if "schemas.openxmlformats.org" not in lnk and "schemas.microsoft.com" not in lnk and "purl.org" not in lnk and "www.w3.org" not in lnk and "go.microsoft.com" not in lnk:
                            urls.update({fle: lnk})
                            urlTable.add_row(fle, lnk)
            except:
                continue

        # Printing table and returning list
        if urls != []:
            print(urlTable)
            return urls
        else:
            return None

    def LocateCDFv2(self, data_stream):
        regx = re.search("d0cf11e0a1b11ae1", str(binascii.hexlify(data_stream)))
        if regx:
            if regx.start() == 2:
                return True
        else:
            return False

    def DisarmMaliciousContents(self, doc_handler, target_contents):
        # Creating a temporary directory
        tmpDir = tempfile.mkdtemp()
        doc_handler[0].extractall(tmpDir)

        # File extension
        ext = self.filename.split(".")[-1]

        # All contents
        allfiles = doc_handler[2] + doc_handler[1]

        # Temp data
        tempdata = []

        # Modification count
        modcount = 0

        # Iterating through target contents
        for fff in allfiles:
            try:
                data = doc_handler[0].read(fff).decode()
            except:
                data = str(doc_handler[0].read(fff))

            # Checking for target contents
            if fff in target_contents:
                # Replacing data
                data = data.replace(target_contents[fff], "CoDeRedlight")
                modcount += 1
            else:
                pass

            # Disarming .bin files
            if ".bin" in fff:
                print(f"\n{infoS} Disarming [bold green]{fff}\n")
                data = "Disarmed!"
                modcount += 1

            # If there is no binary files, we need to check for CDFv2
            tmp_data = doc_handler[0].read(fff)
            if self.LocateCDFv2(tmp_data):
                print(f"\n{infoS} Disarming [bold green]{fff}\n")
                data = "Disarmed!"
                modcount += 1

            # Writing data
            try:
                with open(os.path.join(tmpDir, fff), "w") as f:
                    tempdata.append(f.name)
                    f.write(data)
            except:
                pass

        # Creating a new document with modified parts
        if modcount != 0:
            with zipfile.ZipFile(f"{self.filename}_modified.{ext}", "w") as newdoc:
                for fff in tempdata:
                    sanitized = fff.replace(f"{tmpDir}/", "")
                    newdoc.write(fff, sanitized)
            print(f"{infoS} Modified document saved as [bold green]{self.filename}_modified.{ext}")
        else:
            print(f"\n{infoS} There is no malicious content in this document. [bold green]Nothing to disarm.")

        # Removing temporary directory
        shutil.rmtree(tmpDir)

    def PerformAnalysis(self):
        ioc = {
            "URLs": []
        }
        doc_handler = self.GetStructure()
        if doc_handler != None:

            # Dealing with URL's
            urls = self.GetInterestingURLs(doc_handler)
            if urls == None or urls == {}:
                self.DisarmMaliciousContents(doc_handler, urls)
                return None
            else:
                print("\n[bold magenta]>>>[bold white] Extracting IoC data.")

                # Extracting URLs to another file
                ioc["URLs"] = urls
                with open(f"{self.filename}_IoC.json", "w") as f:
                    json.dump(ioc, f, indent=4)
                print(f"{infoS} [bold green]Done. [bold white]Results saved to [bold green]{self.filename}_IoC.json[bold white].\n")

                # Disarming malicious contents
                print("[bold magenta]>>>[bold white] Disabling malicious contents.")
                self.DisarmMaliciousContents(doc_handler, urls)
        else:
            print(f"{errorS} Error: [bold red]Unable to get document structure.")
            return None

    def DoAnalysis(self):
        # This is our main method
        print(f"{infoS} Starting analysis...")
        
        # Getting document type
        doc_type = self.CheckDocType()
        if doc_type == "Microsoft Word 2007+" or doc_type == "Microsoft Excel 2007+":
            self.PerformAnalysis() # For disarming malicious URL's and binary files. (Also CDFv2)
        else:
            pass

# Main
if __name__ == "__main__":
    print(banner)
    if len(sys.argv) != 2:
        print("Usage: python3 CoDeRedlight.py <filename>")
        sys.exit(1)

    # Getting filename
    filename = sys.argv[1]

    # Checking file existence
    if os.path.exists(filename):
        # Creating object
        doc = CoDeRedlight(filename)
        doc.DoAnalysis()
    else:
        print(f"{errorS} Error: [bold red]File not found.")
        sys.exit(1)