---
layout: post
title: "PicoCTF: riscy-business"
date: 2023-11-06 19:05 -0500
categories: [binary exploitation, remote debugging]
tags: [binary,  exploitation, reverse,  engineering, riscv, gdb, qemu, remote, debugging]
---

Introduction
---
After a bit of a break from posting on here, I've decided it was time to make a new post. 
I needed something a bit more challenging to solve, so the challenge in reverse engineering with only
72 solves looked perfect.

![img-description](/assets/img/6/1.png)
_The challenge..._

So after downloading the attached binary named "riscy", I ran the file command on it:
```console
margo@margo1~$ file riscy
riscy: ELF 64-bit LSB executable, UCB RISC-V, RVC, double-float ABI, version 1 (SYSV), statically linked, stripped
```


I had never seen the architecture type of UCB RISC-V before, so I dug into what RISC-V was. After some looking, I found out that I was able to
emulate the RISC-V architecture with qemu. Great, so now time to debug this to see what happens! After starting qemu with the port 1234, I attempted to
attach gdb to it.

![Desktop View](/assets/img/6/2.png){: width="1025" height="240" }

Well, now what?


> [gef](https://github.com/hugsy/gef) is an awesome tool that completely overhauls gdb. I use it in the section below, so commands may differ with vanilla gdb.
{: .prompt-tip }

Static analysis: IDA Pro
---
Taking a look at the program in IDA Pro, we can see that the program goes to `aThatWasABitTooRiscy` 3 times.

![Desktop View](/assets/img/6/4.png)
![Desktop View](/assets/img/6/5.png)

I think it is safe to assume that these branch instructions execute to `aThatWasABitTooRiscy` if our input does not match the criteria it expects. The first one is not apparent just by looking at it, but the second one is checking if [s0] >= 7. The third one is loading an unsigned byte from s1 and a5, and storing them in a3 and a4 respectively, then checking if they are equal. If they are not equal the program fails, and outputs `That was a bit too riscy for me!`. Presumably this is checking each byte of our input versus the flag. After looking at the program flow, we can take a quick look at the imports, and hex view of IDA.

![Desktop View](/assets/img/6/6.png)
![Desktop View](/assets/img/6/7.png)

Nothing useful in either of these, and the flag is not visible in hex view or strings, so we can assume that it is obfuscated in some way. Time to debug the program and see what's going on!


Dynamic analysis: GDB
---
I looked around the internet researching RISC-V and qemu a bit more, and came up with a solution for debugging the riscv-64 architecture. `gdb-multiarch`.
The command I used to start qemu with riscv was `qemu-riscv64 -q 1234 ./riscy`, and then starting gdb-multiarch.
I use gef, which automatically is applied to gdb-multiarch, so some of the commands I use may differ a bit from vanilla gdb.
To connect gdb to our qemu instance, after running `gdb-multiarch`, we can type `gef-remote localhost 1234 --qemu-user --qemu-binary ./riscy`

![Desktop View](/assets/img/6/3.png)
_Voila! Remote debugging!_
Now that we have our gdb connected to our qemu, we can debug our program. Using `ni` we can step through our program. After a while, we can see we can no longer step over any more. Tabbing into our other terminal, we see that our terminal running qemu is asking us for input:

```console
You've gotten yourself into some riscy business...
Got yourself a flag for me?
>
```
Firstly, I typed in the base for a picoCTF flag, `picoCTF{` and then added random characters afterwards. ex. `picoCTF{test_4_tut0r1al}`. Stepping through our program again, we can see our first conditional statement we identified earlier. It checks if 10 = 10. I am not too sure what the point of this branch instruction is, but the second one we looked at earlier is more significant. It compares the length of our input with 7. The length of our input is greater than 7 so we continue. We soon arrive at another loop that executes 256 times. Presumably this is copying our string to a buffer of 64 bytes. I set a breakpoint on the line after it with `b *0x10090`, and then type `c` to continue. We continue through a bunch of loops and subroutines, which eventually encrypt our password. Now for the comparison. We saw in IDA earlier, the two branch instructions, which we guessed check our encrytped password against the encyrpted flag. If we set a breakpoint a few lines before the comparison `b *0x101c0`, we can get dump the contents of the registers each encyrpted string is stored in. So now for our exploit!

Exploit
---
```py
import string
from pwn import *

# set of chars for bruteforcing later
chars = string.punctuation + string.digits + string.ascii_lowercase + string.ascii_uppercase

# what we assume the flag will start with
flag_known = b"picoCTF{" 

#  ---------------------- [ helper functions ] ----------------------

# function to receive input until we see "gef ->" and can input
def wait_prompt():
    gdb.recvuntil(prompt)

# function to send guess to qemu
def send_guess(guess):
    # coninue our gdb so that we can take input
    gdb.sendline(b"c")

    # go to where we input in qemu and send our guess, then stop after the breakpoint at 0x101c0 is hit
    qemu.recvuntil(b"> ")
    qemu.sendline(guess)
    gdb.recvuntil(b"BREAKPOINT")


def dump_register(reg: bytes) -> bytes:
    # clean our tube, and we will stop at gef ->
    gdb.clean()

    # send our gef command to dump our register
    gdb.sendline(b"pf --lang hex -l 26 $" + reg)
    flag_encoded = gdb.recvuntil(prompt)

    # strip the output of all the unwanted stuff after the flag
    flag_encoded = flag_encoded[0:flag_encoded.index(b"\n")]
    
    # tries to hex-decode our string
    return unhex(flag_encoded)


#  ---------------------- [ main ] ----------------------

# open process to qemu with our binary
qemu = process(["qemu-riscv64", "-g", "1234", "./riscy"])

# open process to gdb
gdb = process(["gdb-multiarch", "-q"])


# now that we are in gdb, connect to our qemu instance and define when to send input
prompt = b"gef"
gdb.sendlineafter(prompt, "gef-remote localhost 1234 --qemu-user --qemu-binary ./riscy".encode("ascii"))
info("gdb attached to qemu!")

# set breakpoint to our desired address (where the check occurs, 0x101c0), and continue to where input is taken
gdb.sendlineafter(prompt, b"b *0x101c0")
wait_prompt()

# send input to gdb with the flag we know already
send_guess(flag_known)

# dump the value that our input is being compared against
wanted_val = a5 = dump_register(b"a5")
msg = "encoded flag: " + str(wanted_val)
info(msg)

warning("starting bruteforce!~")
with log.progress("flag ->") as progress:
    for i in range(len(flag_known), 52):
        leng = len(flag_known)
        found_char = False

        for c in chars:
            guess = flag_known + c.encode("ascii")

            gdb.sendline(b"set $pc = 0x10112")
            wait_prompt()
            send_guess(guess)

            # dump the register that our input is in
            input = dump_register(b"s1")

            # if the dumped registers up to the length of our flag match, we found the right character
            if input[:i + 1] == wanted_val[:i + 1]:
                found_char = True
                flag_known = guess
                progress.status(str(flag_known))
                break
            
        if not found_char:
                warning("letter not found")
                break

warning("FLAG: %s" % str(flag_known))
```

![Desktop View](/assets/img/6/8.png)

Voila! Our flag is printed nicely. Albeit this script is somewhat slow, but it works as expected.

Conclusion
---
All in all, this challenge was tough for me. I spent over 8 hours just stepping through the program and commenting what each line the program was on did in IDA. 
When I realized that most of the program before the comparison was not worth reading, I felt silly. But overall it was a great learning experience for me, allowing 
me to hone my skills using:

- IDA Pro
- GDB
- QEMU

And also learn about the RISC-V instruction set as well. If you read this far, thank you for reading :)