<h1 align="center">🔎 IDAFuzzy 🔍</h1>
<p>Fuzzy searching tool for IDA Pro.</p>

## What's IDAFuzzy?
IDAFuzzy is fuzzy searching tool for IDA Pro.
This tool helps you to find command/function/struct and so on.
This tool is usefull when
1. You don't remember all shortcut.
2. You don't remember all function/struct name exactly.

This tool is inspired by Mac's Spotlight and Intellij's Search Everywhere dialog.

(Only IDA Pro 7 is tested.)

## Requirements
It requires <a href="https://github.com/seatgeek/fuzzywuzzy">fuzzywuzzy</a>. 
```
pip install fuzzywuzzy[speedup]
```

## Installation
Put ```ida_fuzzy.py``` into ```plugins``` directory.

## Usage
Just do as follows.

1. Type SHIFT+SPACE.
2. Type as you like. (e.g. "snap da")
3. Type TAB for selecting.(First one is automatically selected.)
4. Type Enter to (execute command/jump to address/jump to struct definition).

<p align="center"><img src="https://github.com/Ga-ryo/IDAFuzzy/blob/master/screenshots/idafuzzy.gif"></p>


### Jump to function
---
<p align="center"><img src="https://github.com/Ga-ryo/IDAFuzzy/blob/master/screenshots/jumpf.gif"></p>

### Jump to struct definition
---
<p align="center"><img src="https://github.com/Ga-ryo/IDAFuzzy/blob/master/screenshots/structdef.gif"></p>
