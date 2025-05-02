# Engineering-Everything-with-eBPF

A complete Hugo/Docsy site for the **Engineering Everything with eBPF** book, including all source, code examples, and figures.  

Visit the live site at: https://ebpf.hamza-megahed.com  


## 🤝 Contributing

We’re happy you want to make **Engineering Everything with eBPF** better.  
The steps below keep changes smooth and easy.

1. **Open an issue first**
    - Create a GitHub issue for typos, unclear text, new examples, or bugs in sample code.
    - Show what you saw and what you expect instead. Screenshots or terminal output help a lot.
        
2. **Fork the repo and create a branch**
    - Fork, then name your branch clearly—­for example `fix-ringbuf-example` or `add-cgroup-section`.
        
3. **Write in the same simple style**
    - Short sentences, plain English.
    - Use fenced code blocks (` ```c ` for C, ` ```bash ` for shell).
    - Wrap Markdown lines at about 80 characters so diffs stay readable.
        
4. **Test what you add**
    - All examples must build and run on **at least Linux 6.12.22, Clang/LLVM 17, and libbpf 1.5—or newer**.
    - If you change existing code, run it to confirm the output still matches the book.
    - Add a short comment showing expected output if it helps readers verify success.
        
5. **Open a pull request**
    - Reference the related issue (for example, `Fixes #123`).
    - In the PR description, explain **why** you made the change and **how** you tested it.
    - CI checks will compile the code and build the book; please wait for them to pass.
        
6. **Review process**
    - We aim to review within a week. Friendly suggestions are normal—feel free to ask for clarification.
    - Once approved, a maintainer will merge and include your name in the release notes.
        
7. **Licensing**
    - **Kernel eBPF source files**
        - If the file contains
            ```c
            char LICENSE[] SEC("license") = "GPL";
            ```
            it is contributed under **GPL-2.0-or-later** so it can use GPL-only helpers.
        - You may instead set the string to `"BSD"`, `"MIT"`, or any SPDX-compatible identifier if you prefer a more permissive license.
            - **Important:** the kernel will then _not_ allow GPL-only helpers; choose this path only if your code does not need them.
            - State your chosen license in the file header so readers know the terms.    
    - **User-space loaders, scripts, and utilities** are **Apache 2.0** by default (mention in the header if you prefer GPL).
    - **Book text and diagrams** remain **Creative Commons BY 4.0**.
8. **Code of Conduct**
    - We follow the [Contributor Covenant v2.1](https://www.contributor-covenant.org/). Please be respectful, patient, and welcoming.
That’s it! Thank you for helping more people engineer everything with eBPF.

## 📜 License

**Book text & figures**: Creative Commons Attribution 4.0 (CC BY 4.0)&#x20;
**Kernel-space examples**: GPL-2.0-or-later
**User-space tools & scripts**: Apache 2.0

