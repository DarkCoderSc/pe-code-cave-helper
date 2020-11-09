# Portable Executable Code Cave Helper

This tool was created during my Offensive Security Certified Expert (OSCE) preparation. *This is far from being a production application but was created to master one technique of backdooring / obfuscating PE Files*.

I tested this script on few famous packed or not packed Microsoft binaries. It works perfectly.

One important cool missing from this tiny script is the possibility to create artificial code caves (One example among others would be to artificially create a new PE Section). If I find the motivation I will implement this feature asap. 

Use such automated tools when you already know how to do it manually.

## Features

* Search for code caves in executable sections.
* Encrypt / Obfuscate sections.

## How it works

The script will patch target file PE Header and update its entry point to a desired code cave (script scans for code caves and ask user to choose which one to use).

The script will then inject instruction on code cave to:

- Save CPU Registers and flags.
- Save stack pointer.
- Execute an optional payload.
- Deobfuscation routine if requested (section obfuscation). 
- Restore stack pointer to its original state
- Restore CPU Registers and flags.
- Redirect back execution to original entry point.

What interesting thing is the way I decided to restore ESP (stack pointer). I'm using a quite similar method as for Egg Hunters to search and restore original stack pointer value.

## Available Commands

- `-f / --file` : Valid PE File location (Ex: /path/to/calc.exe).
- `-p / --payload` : Shellcode Payload (Example: \"\\x01\\x02\\x03...\\x0a\").
- `-x / --encrypt` : Encrypt main section (entry point section).
- `-k / --encryption-key` : Define custom encryption key (1 Byte only).
- `-c / --cave-opcodes` : Define code opcode list to search for.
- `-s / --cave-min-size` : Minimum size of region to be considered as code cave.
- `-e / --egg` : Define a custom egg name (ESP Restore Mechanism).

## Screenshots

![Image 1](https://i.ibb.co/bb8WshH/Screenshot-2020-11-09-at-15-46-59.png)
![Image 2](https://i.ibb.co/TMk94WF/Screenshot-2020-11-09-at-15-47-38.png)

## TODO

- Better Obfuscation / Encryption mechanism.
- Artificial Code Cave Creation.
- Better Comments.
- Option to define which sections to obfuscate (Actually, default is all).


## Changelog:

- 0.1 : First release

