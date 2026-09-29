# CSAW Quals 2026

> A/N: Although I solved more challenges the ones written up here, these are the only ones I felt had enough substance to warrant a write-up.

## rev/Machine Head

### The problem

- We are given a simple binary with a simple command line argument - input the flag, and it tells you the if it's the master key, otherwise, you are wrong.
- The challenge description mentions the machine is a custom design - using a custom opcode table. 

### Figuring it out

- First idea of course is to throw it into a disassembler and decompiler. BinaryNinja is still my tool of choice. 
- analysis of the binary reveals two main features:
  - a large chunk of data (nearly 2000 bytes) sitting in `.rodata`
  - a loop over a set of if-statements performing operations in `main`
- given the hint of a custom opcode table- its pretty clear what the program is doing: `main` is an interpreter for the custom instructions found in the large data chunk.

![Image](<attachments/Pasted image 20260928184605.png>)

### Solving it

- Custom interpreters like this are a relatively common pattern in CTFs, so this mostly involves some simulation and reversing (as the category name suggests)

#### Step 1 - Interpreting the custom opcodes

- Instead of working directly with the program data, its easier to convert it into a common language instead.
- Based on the set of if-statements, there are a total of 9 opcodes, with each instruction being 3 bytes large, consisting of `opcode, a, b`, where `a` and `b` serve as the usual register values or "inputs" for the instruction.
- based on the body of the if-statements, each opcode performs a different operation, and writing out what each opcode does plain text helps identify what the program does

```python
NAMES = {
    0x91: "load  buf[{a}] = input[{b}]",
    0x24: "add   buf[{a}] += {b}",
    0x1d: "mul   buf[{a}] *= {b}",
    0x7a: "xor   buf[{a}] ^= {b}",
    0xb2: "rol   buf[{a}] <<<= {b}",
    0x6d: "addr  buf[{a}] += buf[{b}]",
    0x4e: "xorr  buf[{a}] ^= buf[{b}]",
    0xa7: "cmp   buf[{a}] == {b}",
    0xe0: "end",
}
```

- with a grand total of 1914 bytes in the data block at 3 bytes per instruction, there were a total of 638 instructions in the program. 
- there is one other important element to the program. `var_18` is the working space in which the opcodes operate. `a` is always either 0, 1, or 2, and the `*(&var_18 + rsi)` strongly indicates an array like structure acting similarly to a buffer. This is where all these calculations are stored.
- for the sake of time, the printed list of all 600+ instructions were provided to Claude to find patterns in the operations, revealing a core loop in the instruction logic:

#### Step 2 - Interpreting the program itself

- Analysis revealed that the program's instructions act in a 12 instruction loop:
  - `load` in a byte from the input into a scratch byte in the buffer
  - `xor` the scratch byte with some number (`c1`)
  - then `add` with some number (`c2`)
  - then `rol` (rotate left) by some number (`r`)
  - then `xor` with 195
  - then `mul` by 27 
  - then `xor` with a saved "running state" byte in the buffer
  - `cmp` the resulting scratch byte to some target number (`target`)
  - `load` the same input byte into a different scratch byte
  - now update the "running state" buffer by performing `add` with the input scratch byte
  - then `rol` (rotate left) by 3
  - then `xor` with 158
- In python code it looks something similar to this, where the constants that changed with each loop are defined by variables:

```python
running_state = ? # depends on previous iteration
c1, c2, r, target = ? # constants are different across loops
value = (((rol(((input[i]^c1) + c2), r))^195)*27)^running_state
if value == target:
  # good! continue on
else:
  # bad... break loop and exit with a fail
running_state = rol((s + input[i]), 3) ^ 158
```

> Note that all these values and operations are performed on a 1 byte data size - overflows are common and just truncated

- the only 2 exceptions to this loop is the setting up of the running state to 60 and the `end` instruction at the end of the block.
- with the program successfully defined, we can create a solve script.

#### Step 3 - Creating a solution

- The first thing to note is in order to find the value of `input[i]`, we need to do two things:
  - reverse each operation performed on `input[i]` by starting with the `target`
  - calculate the running state like normal after obtaining `input[i]`
- In addition to the actual solution loop, further parsing of the data is need to extract all of the constants from the instructions.
- Here is the full solution script, with aid from Claude to read and parse the binary data:

```python
import sys

BINARY = "./masterkey"

# from readelf -S to get real memory address location
SECTION_ADDR = 0x402000    # the "Addr" column
SECTION_OFF  = 0x2000      # the "Off" column

# from Binary Ninja
START_VADDR = 0x402040     # data_402040
LENGTH = 1914              # in bytes

# convert the virtual address to a position in the file
file_offset = START_VADDR - SECTION_ADDR + SECTION_OFF

with open(BINARY, "rb") as f:
    f.seek(file_offset)
    code = f.read(LENGTH)

def instr(j):
    return code[3*j : 3*j + 3]        # (op, a, b)

# parse data for constants
params = []
for k in range(53):
    base = 1 + 12*k
    c1     = instr(base + 1)[2]
    c2     = instr(base + 2)[2]
    r      = instr(base + 3)[2]
    target = instr(base + 7)[2]
    params.append((c1, c2, r, target))

# reverse of the rotate left function
def ror8(x, n):
    n &= 7
    return ((x >> n) | (x << (8 - n))) & 0xFF

# undo operations on input from target
inv27 = pow(27, -1, 256)
def unscramble(target, s, c1, c2, r):
    v = target ^ s
    v = (v * inv27) & 0xFF # note: single byte underflow truncation
    v = v ^ 195
    v = ror8(v, r)
    v = (v - c2) & 0xFF
    v = v ^ c1
    return v

# main loop
s = 60 # initial running state
output = ""
for block in params:
    c1_k = block[0]
    c2_k = block[1]
    r_k = block[2]
    target_k = block[3]
    x = unscramble(target_k, s, c1_k, c2_k, r_k)
    output += chr(x)
    s = rol8((s + x) & 0xFF, 3) ^ 158  # update running state

print(output)
```

This solution script then outputs the flag:

`
csaw{cl1mb1ng_th3_v1rtu4l_st4ck_0n3_0pc0d3_4t_4_t1m3}
`

### Retrospective

This was definitely a classic reverse engineering problem, and I quite enjoyed my time solving this one. Unfortunately, due to it being a classic reverse engineering problem, AI was able slop this and a couple other problems all the way down to the base 50 points, which is quite unfortunate given the amount of time I spent on this problem. I think the crazy part about this situation, funnily enough, was that the sanity check problem ended up being "more difficult" in that it had less solves than all of these AI slopped challenges. And although the organizers brought up the point value of sanity check from its usually 1 point to 250, based on the dynamic scoring of the rest of the challenges, that 250 point value actually fit in reasonably well.

## misc/The Vantage Job

### The problem

- This challenge follows a thief which goes by "Ferryman", who robbed a hardware wallet full of bitcoin. The thief cannot resist leaving a small paper trail, and we follow this trail to the flag.
- This challenge contained two files: "evidence_01.pdf" and "evidence_02.txt"
- Without much setup to go off of, we get straight into solving it:

### Solving it

#### Puzzle 1

- The text file reveals a simple poem:

```txt
Paper keeps what paper hides,
pale as breath on frosted glass.
Not empty only patient,
waiting for the light to pass.
```

- this poem makes more sense after inspecting the pdf, which appears to be completely blank. 
- of course, the PDF, is not actually blank, and opening it in a text file reveals that it has several objects, including a title and an image object. 
- While the title is not so important, the image clearly is, so we run `pdfimages` on the pdf and extract the image. 
- Of course this image is also seemingly blank, but some quick image analysis using the `imagemagick` suite shows that there is some slightly less than white pixels within the image, and further image process reveals this following image:

![Image](<attachments/Pasted image 20260928201557.png>)

#### Puzzle 2

```txt
A bot has no thumb, no whorls, no line,
yet it wears one word as a secret sign.
Whisper it quiet, not loud, not seen --
slash the fingerprint, and it'll know what you mean.
```

- Admittedly, I got embarrassingly stuck on this one. I analyzed the PDF and text file even further for any more clues but there were no more, so we return to the poem as the only hint.
- The poem mentions a bot, wearing "one word", whispering to it, and slashing a fingerprint. The only reasonable context this could have would be that the main communication for the CTF is ran through discord, which has bots.
- In the end, the hint of the name "Ferryman", which searched in the CTF discord, revealed a discord bot named "ferryman_vt"
- the rest of the poem explains what to do - "whisper" meant sending a DM to the bot, and "slash the fingerprint" literally meant `/fingerprint`, as in a bot command, revealing the next poem:

![Image](<attachments/Pasted image 20260928202249.png>)

#### Puzzle 3

```txt
Clever, aren't you, finding me here — 
a bot with no face, but I'm still near. 
I won't spell out where I've been, 
but a name's a name, wherever it's seen. 
Look twice at the one who's typing this line — 
he answers to it everywhere, all the time.
```

- the "answers to it everywhere" and "a name's a name, wherever it's seen" are strong indications of OSINT - specifically a case of a reused username

##### An Unfortunate Shortcut

- after taking "ferryman_vt" to some username searching websites, I discovered an account on Twitter/X created in September 2026, the month of the CTF. This was a promising lead, although there was nothing on the actual profile besides a short bio.

![Image](<attachments/Pasted image 20260928203223.png>)

- Searching the images revealed them to be unrelated to the search
  - other note: not sure if this is the actual source, but the banner image appears to be at the very least used as the background image of a [short EXEcutable Mania (sonic.exe Friday Night Funkin' Horror Mod) fan animation](https://x.com/djawesomeyt/status/1887184180124983702/)
- Interestingly, however, this account happens to be followed by a single person - Saatvik Sachdeva (@saatviks28), which happened to be following some other interesting accounts (which will be discussed later).
- Unfortunately, after the CTF, it was confirmed by the challenge author that this account was not part of the intended solution to the CTF.

##### Back to the intended path

- The actually intended path was supposed to be through Instagram - however this is made more difficult for username sites to search as Instagram to view profiles and the such. 
- The Instagram for the account has a single post as shown:

![Image](<attachments/Pasted image 20260928210039.png>)

- This involves a classing bit of hidden messaging. As hinted to with the lines "read the letters leading", taking the first letter from each line in the message spells out "TOCKFERR", and the -X implies we are hopping over to Twitter/X
- the Ferry (@tockferr) Twitter account has some post history as follows:

```txt
Steel and glass, a patient face, ticking softly, keeping pace.
Sold a dial, kept the case, something you just can't replace.
New piece landed today. Not for sale. Not yet.
Some of us just collect. Some of us collect quietly.
PINNED - Thursday well spent. [clock emoji] (yes, I'm the same everywhere - try harder)
```

- One of these posts contains a gif comment from Geneva (@timepiece_ferr). The similar "ferr" ending implies this is another profile worth investigating:

![Image](<attachments/Pasted image 20260928210815.png>)

- Note: Screenshots were taken AFTER the infrastructure for the CTF was taken down. The link in the post used be for https://tinyurl.com/vantage-job
- The first thing that jumps out is the 8 character alphanumeric code in the bio of the account. Due to the TinyURL link in the post, this immediately reminded me of the short codes used for these URL shortening services. Trying this out led to a pastebin of a massive amount of encoded text.

#### Puzzle 4

- Following the TinyURL led to this paste file: [Link to pastebin](https://paste.d4rk4shes.com/)

![Image](<attachments/Pasted image 20260928211749.png>)

- This file was absolutely massive, and looked roughly like it was encoded in Base64, so I took the first line and placed it into a base64 decoder:

![Image](<attachments/Pasted image 20260928212006.png>)

- This revealed some "UNICODE" metadata, which, after ignoring all the non-UTF-8 characters, reveals our flag.
- An alternative way to solve this was to recognize the header `/9j/` (or just put it into CyberChef) as a `.jpeg` header. Converting the text into a jpeg image allows you to read the properties of the image directly (either through Windows properties or `exiftool`)
And here's the flag in all its glory:

`
csaw{cr0ss_pl4tf0rm_carel3ssness}
`

### Retrospective

This challenge was a nice breather from all the web challenges me and my team were unfortunately unable to solve. I really enjoy the `misc` challenges as they allow me to flex a wider range of puzzle solving muscles with these multi-step solutions. Besides the unfortunate shortcut, I think the challenge is probably my favorite of the event.
