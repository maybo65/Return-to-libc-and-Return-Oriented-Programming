
### Motivation (and some history)
The buffer overflows attacks we exploited so far, rely on writing our code into the stack and execute it, but the ability to do so is pretty much not a realistic assumption. Today, almost all of the operation system implements various [protections on the executable space](https://en.wikipedia.org/wiki/Executable_space_protection), typically by marking the stack (and/or other areas of the memory) as non-executable. This prevented the classic buffer overflow attack we exploited so far.

But, in 2006, an attack called  [return-to-libc](https://en.wikipedia.org/wiki/Return-to-libc_attack)  was  [published](https://www.exploit-db.com/papers/13204/), describing a mechanism that enables obtaining a shell in some cases, even with a non-executable stack. We’ll implement this technique in the first part.

In 2007, a significantly improved version of this attack was published under the name  [return oriented programming (ROP)](https://en.wikipedia.org/wiki/Return-oriented_programming). This enabled executing far more sophisticated codes that return-to-libc. We’ll implement this technique in the second part.

# Part A
Our target, as in the previous exercises, is the sudo program. We now have two changes:

1.  The password argument is passed in a [base64 encoding](https://en.wikipedia.org/wiki/Base64), which is then decoded by the program itself. 
    
2.  This time, the sudo program comes with a non-executable stack 😈

**In this question, we’ll implement the return-to-libc attack, to open a shell with root privileges.**
## q1.a
As in the previous BOF exercises, as a starter point, we are going to send payload that will cause our program to crash. Lets take a look at the sudo program:
![image](https://user-images.githubusercontent.com/112778430/190854927-57260750-9cbe-4e5b-8627-116659f32c7e.png)

Lets notice that the buff size is 65, and there is no check of the len of the password that is send to it. So, sending a really big password will cause that even after the decode there's goint to be buffer overflow. This will make the sudo program to crash. so, we are going to send:
AAAAAAAABBBBBBBB....ZZZZZZZZ (every letter 8 times) in order to create the crash.

## q1.b
Now, after we crashed the program (in q1a.py), we will use the core file created in order to analyze the program memory address, and from that- sending the sudo program a payload that will open a shell for us. 
So, as we said, the stack is non-exactable, so we can write code inside our payload (it simply won't run). But, some areas in the memory of the program must be exactable (otherwise we couldn't run the code). One of this areas is **the .text section inside the libc.so(.6)** .This is where the assembly code resides. 
### Why do we care about executable parts of the stack?
Lets remember how the stack works:
Every time a function is being called, the caller function push the current address of the next instruction into the stack, and all of the function variables (before it). 

When we are returning from the function, we are reading the value pushed into the stack as the return address. so, if we could override the return address with the address of some other function in the code we could make the program to jump there, instead of return to the caller. 

## Plan Attack
we are going to find the address  of the __system function inside the .text section inside libc.so. Once we got this, we will need to find also need to find the address of the bin/sh/ string in the memory. We cant just write it ourself and enter a pointer, because again, the stack is non-executable and we wont be able to get it dynamically using our shellcode as we did in the last three exercises. But, Lucky us, this string is part of some strings which are constants in the libc library, so we will be able to find it inside  the .rodata section (this is where initialized constant data, such as strings, is stored).

So, our plan is to make the stack look pretty much like that:
![image](https://user-images.githubusercontent.com/112778430/190856396-149be794-8b86-472e-a956-634ddde36293.png)

## Attack Implementation
First, I needed to find the address of system(). Using the core file I got from crashing the program, I opened GDB and did "print &system". This gave me:
![image](https://user-images.githubusercontent.com/112778430/190856534-3dbcf7e0-f37e-4a3c-8d04-17880b12c87d.png)

By that I got system address- 0xb7b4f040.
Next, I needed to find an occurrence of "/bin/sh". To do this I first used info files command, which led me to find out that the .rodata section is between 0xb7c7c000 - 0xb7c9fb98. 
Then, I used the - find 0xb7c7c000, 0xb7c9fb98, "/bin/sh" command, and got: 0xb7c96338. This give us the address of the wanted string (we can verify that by running print (char*) 0xb7c96338).
In addition, I found out that the return address of the function is in address 0xbfffe03c (by looking on the value of eip, and matching it to memory image. this means that the letters (in q1a.py payload we sent) that caused the crash are QRRR. 
The first R is in distance of 8*(82-5)=136, meaning that there are 135 chars we need to fill if we want to exactly override the return address.

Now, we can open a shell by locating the address of system right instead of the return address we are going to override, and locating the right arguments above (a pointer to the string, and a pointer to the pointer of the string). 

so, we are going to build the following password:
*135 bytes of 'a'- this is only for padding* + *system return address in LI* + *doesn't matter* + *the address of \bin\sh* 
 
 # q1.c
 Ok cool, so we have a shell! But small problem- after the program ran- it crashed. Its not such a problem, because we already have a shell, but it is better to leave as little as possible traces behind us (And a core dump is a pretty big trace).
 So, this time, we are going to open a shell, but also exit cleanly.
 
 ## Crash Cause
 Lets think what happend again by looking at the stack: 
 ![image](https://user-images.githubusercontent.com/112778430/190856396-149be794-8b86-472e-a956-634ddde36293.png)
 So, after the system function being called it did open a shell for us. but, after this function finished, it's also tried to jump to the next instruction, meaning- the address of its caller. The system function expecting to find this address in the purple sloth, but we didn't provide anything there.
 ## Plan attack
 So, instead of just putting the system address, we are going to put the address of exit() in the purple sloth. The exit function is getting exit code as a variable, and it will be in the blue section:
 
 ![image](https://user-images.githubusercontent.com/112778430/190857202-2871f4bd-24c3-434b-be25-4d11f57622ef.png)
 
*notice that we couldn't do that with other function beside exit. This because that the next function we would have put there, would have tried to take it's return address from the green sloth, which is the 1st variable to system, and that would have cause us to crash.*

## Attack Implementation
So, we need the exit() address. This one is also located inside .text in libc, so I found it exactly as I found the system address. as exit code, we will chose 0x42 🚀

So, our payload is going to look like that:
*135 bytes of 'a'- this is only for padding* + *system return address in LI* + *exit address* + *the address of \bin\sh* + "exit code- 0x42" 

# Part B
So, this was very cool, but we are still pretty limited, because as I mention earlier, we can only call one function and then exit, and this function complete. Now, we are going to work a bit harder, and will get the option to build code as we desire, using a ROP attack.
ROP attack is basically to do what we just did in q1, but instead of jumping to a function, we are going to jump straight to instruction and build an assembly code on the with those instruction. We will call each of this instruction's group a gadget. notice that each gadget must finish with ret, so we could jump to the next gadget. meaning that now we are simply going to write on the stack the address of the different gadgets, and because of the fact that after ret we are jumping to the address stored on the stack, we will be able to do so. 
### small tip
the stack is now basically our code itself, meaning that esp is now basically eip. We could do many interesting things using manipulation on esp this way, like loops, condition and other stuff. I recommend read about this a little more because it can be a bit tricky to understand on the first time. 


## q2
In the next questions, we’re going to implement ROP attacks! However, implementing a ROP requires having a working “gadget search engine” that can search the memory and locate gadgets!

The search engine we’ll implement will be fancier than what you might expect at first - it will support searching for the same instruction with multiple combinations of registers at once, so that we don’t have to try all combinations manually. For example:
![image](https://user-images.githubusercontent.com/112778430/190857968-0c2c037a-2a20-459f-9dfe-81fb7a469a3e.png)

In order to build the engine, I had to do two things:
1.  Using the techniques mentioned in part a, I used GDB to create a dump of the .text section of libc, called this file libc.bin and saved it.    
2.  Implement all the relevant functions in search.py
    
*Full details available inside search.py.*
    

# Part C - Warming Up with ROP

In this question, we’ll use ROP to create a basic “write gadget”. A write gadget is a gadget that receives a memory address and a (4-byte) value, and writes the value into the given memory address - similar to (MOV [addr], value).

We will use this gadget to override the auth variable of the sudo program, to make it print Victory!

## Attack
Lets notice that in order to print victory in the sudo program, the value of the auto variable must be 0. We are going to build a payload that changed the memory of auth dynamically at runtime: 
first, I used the find_all_formats function, with mov [{0}], {1} in order to find a gadget that is going to be suitable. after that, I found  out that mov [eax], edx is in the file. So, I just needed to look for pop eax and pop edx. I found them to and could write my code. 
I got the addresses of those gadget using the find function. I also got the auth address using IDA, and, the return from the function (this will allow us to print victory). finally, built the password: 
*135 bytes of 'a'- this is only for padding* + *"pop eax" gadget address* +*auth address* + *"pop edx" gadget address* + *0x1* + "mov [eax], edx" gadget address* + "the return address to the rest of the code, after we alter auth". 

**this will cause:**
1. eax < address of auth
2. edx < 0x1
3. mov[eax], edx
4. return back, outside of the function to the original return address we overrode, and call puts, after auth=1, which will cause printing victory as needed. 

# Part D- The interesting part 😈
In this final question, I’ll needed to implement a ROP that will cause the sudo program to run in an endless loop and print the string "Take me (<YOUR_ID>) to your leader!". This means that the ROP we want to create, if your ID is 123456789, is the equivalent of:
 ![image](https://user-images.githubusercontent.com/112778430/190866648-652073ac-909b-4357-a3c7-b3a04b46da97.png)

### Our ROP we will construct will be roughly as follows:
1.  Load the address of puts into EBP
2.  Jump to puts
3.  Address of a gadget to “skip” 4 bytes on the stack
4.  Address of our string
5.  Loop back to the second step (2 - Jump to puts)
    

*We will assume the stack is always in the same address, so we can know where on the stack the loop begins.*

## The Attack
our stack is going to look like that after sending our payload:
![image](https://user-images.githubusercontent.com/112778430/190867488-0e2f6302-8095-45b7-b4f0-7b6f9609c4ec.png)

**lets take a look on the code we build upon the stack. It is built as follows:**
1. "pop ebp" gadget address, and after that the address of the puts function. This will cause this address to be stored in ebp (because pop ebp take the first value on the stack, store it inside ebp, and then move esp up by 4).
2. address of puts function, following the address of gadget2 (we'll get that in a sec), a pointer to the string we want to print. this will make a call to the puts function with the string as argument, and after that we will return to the address of gadget2, so it will be executed.
* gadget2- add esp,4. this will be called after the return from the puts function. We need that so we could just skip the pointer to the string, and not trying to return to there. meaning that it will cause esp just point directly to 3. This is necessary in order to make sure that the next gadget that is going to be executed is gadget(3) - the loop back. **otherwise, esp would point to our string, and trying to execute it as commands.** 
3. pop esp gadget address, following the address of the memory address we want (2). this will cause that esp will point back to the call to that address, and we will start execute our code again. this will result an endless loop of our code. 

***so, our password is going to look like that:***
 *135 bytes of 'a'- this is only for padding* + *"pop ebp" gadget address* + *address of puts* + *address of puts, again- lets call this location- @* + * "add esp, 4" gadget address- this is here to be the return address from puts* + *pointer to the requested string to be printed- this is here as an argument for puts* +"pop esp" gadget address* + *address of the (@)* + our string we want to print. this we will get by calling the get_string function with my ID. 
 
### So, how the puts function does not running over it own return address? 
if we look at the disassembly of the puts function we will find out that the first thing that the puts function does, is to push ebp. this will indeed cause an override of the code we worte, but only gonna override the address of puts, with the address of puts (because this what we put in ebp). After that, esp is under our relevant part of our ROP, so this is not matter if the function gonna override some other things. lastly, the puts function pop the value she pushed back to ebp. this will cause that esp is going to be right back at the right place, and ebp will contain the address of puts again. this will keep things just as before we called the puts function. 

### So, how did we put our string in the code?
in order to include my string in the ROP, I simply called the get_string function with my ID, and add that to the end of the ROP. this cause the string to be in the memory, right after the ROP itself, on the stack as well. From a simple calculation I got the address of that location. 

 
And that is! we build an endless loop using ROP 😊
