"""ctfkit - CTF helper for Linux ELF x86-64 (rev + pwn).

A small toolkit that automates the boring first 10 minutes of a rev/pwn
challenge: triage, exploit-skeleton generation, ROP/GOT helpers.

Works best with pwntools installed; degrades gracefully to readelf/objdump/nm
so it stays useful even on a bare remote box.
"""

__version__ = "0.9.0"
