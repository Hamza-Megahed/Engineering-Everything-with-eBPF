---
title: Preface
description:  Welcome message explaining what you will learn and how to use the book.
weight: 5
---

Hello and welcome. **Engineering Everything with eBPF** is your friendly guide to eBPF on Linux. eBPF lets you run tiny programs inside the kernel so you can watch what the system is doing, filter network traffic, and even add safety checks—all without changing kernel source code. That sounds powerful, and it is. But it can also feel confusing the first time you see strange section names like `SEC("xdp")` or long helper calls. Do not worry. Every chapter walks you through one small idea at a time, then shows a real example working on your own machine.

**Why this book exists**  
When I began learning eBPF, I kept bouncing between blog posts and mailing-list threads, piecing things together. I wrote **Engineering Everything with eBPF** so you do not have to repeat that maze. You will start by loading a five-line program, see the result right away, and gradually build up to practical tools for tracing disk I/O, shaping network traffic, and securing containers.

**Plain language, lots of examples**  
I use short sentences, clear words, and plenty of code. Each new term—_map_, _verifier_, _tail call_—appears next to a tiny program you can copy, run, and explore. After you run the code, the explanation will make more sense. If something still feels cloudy, keep reading; later chapters revisit the idea from a different angle.

**Tested environment**  
All code listings were compiled and executed on Linux kernel 6.12.22, with Clang/LLVM 17 and libbpf 1.5. If you use this kernel (or a newer one) the examples should work exactly as printed. When newer kernels add handy helpers or map types, I point them out and tell you whether you need to adjust your code.

**What you need**

- A Linux box or virtual machine with kernel 6.12.22+
- `clang`, `lld`, `make`, and typical build tools
- Root access (or the `CAP_BPF` capability) to load programs
- A sense of curiosity—nothing else
    

**How to read**  
_Skim first, run later._ Browse the chapter, copy the program, run it, then come back and read the full explanation. Learning speeds up when you see the output with your own eyes. If a term is still unclear, do not worry; it often becomes obvious after the next example.

By the final chapter you will have a small toolbox of eBPF programs you can adapt to real-world tasks—debugging, performance tuning, or keeping a service safe. Take your time, run the code, and enjoy the process. Everything will click, step by step. Let’s begin our journey into eBPF together.