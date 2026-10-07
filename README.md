# Fragments
Fragments is a simple CLI utility built with Python that allows you to divide
and encrypt files. It was a small learning project to understand encryption and 
hashing better. It is easy to use and has probably been implemented 
professionally by others but this is just something I wanted to because it 
offered a solution to a problem I had.

### Requirements
- Python >= 3.12.10

### Usage

Creation of Fragments:
```
fragments.py -c [ file name ] -p [ password ] -s [ number of slices ]
```
Restoration of Fragments:
```
fragments.py -r [ file name ] -p [ password ]
```
**Note**: For restoration of files, the fragments need to be present in the
root of where the command will be executed.

### Building Fragments
Fragments uses pyinstaller to build it into an easy to use executable.
```
pyinstaller --onefile fragments.py
```
The resulting file can be configured into your system's PATH for
easy access system-wide.

### How does it work?
In brief, Fragments uses Argon2id with a cryptographically secure, randomly 
generated salt value as ingredients to generate a hash. This hash can be used
as a key for a 256-bit AES cipher which is then used to encrypt and protect
the files at rest.

I have talked more in-depth about this on my blog. You can read 
more about it [here](https://monospace.lol/).


