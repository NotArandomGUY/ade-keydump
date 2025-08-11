# ADE Keydump

A little tool that will attempt to decrypt & dump epub as you open it in Adobe Digital Editions (for Windows)

There's better tool to remove DRM from ebook and it's not difficult to find,
this is mostly just a result of lack of google search (and maybe for fun) :P

## Disclaimer

Use at your own risk
- Windows Defender will think this is bad (due to dll injection) (might or might not fix it later)
- Might get your device/adobe account banned or something idk
- Probably will crash randomly ;)

## Usage

### Step 1
Start the program/tool

Options:
1. Start ADE then run `keydump.exe pid <pid of ADE>`
2. Start ADE then run `keydump.exe name DigitalEditions.exe`
3. Rename original `DigitalEditions.exe` to `DigitalEditions.core.exe` then
   rename `keydump.exe` to `DigitalEditions.exe` and double click it

### Step 2
Open the epub you want to dump in ADE

### Step 3
If everything didn't crash & burn, the dumped file should be right next to the original file (Usually in `Documents\My Digital Editions`)

## Building
Open solution in Visual Studio and figure it out yourself, shouldn't be too difficult & I'm too lazy to explain

Note: You might want to set platform to x86 before building it