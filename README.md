# Return-to-libc-and-Return-Oriented-Programming
Return-to-libc and Return Oriented Programming


### Motivation (and some history)
The buffer overflows attacks we exploited so far, rely on writing our code into the stack and execute it, but the ability to do so is pretty much not a realistic assumption. Today, almost all of the operation system implements various [protections on the executable space](https://en.wikipedia.org/wiki/Executable_space_protection), typically by marking the stack (and/or other areas of the memory) as non-executable. This prevented the classic buffer overflow attack we exploited so far.

But, in 2006, an attack called  [return-to-libc](https://en.wikipedia.org/wiki/Return-to-libc_attack)  was  [published](https://www.exploit-db.com/papers/13204/), describing a mechanism that enables obtaining a shell in some cases, even with a non-executable stack. We’ll implement this technique in the first part.

In 2007, a significantly improved version of this attack was published under the name  [return oriented programming (ROP)](https://en.wikipedia.org/wiki/Return-oriented_programming). This enabled executing far more sophisticated codes that return-to-libc. We’ll implement this technique in the second part.
