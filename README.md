# firebirdDump
Uses the default firebird database credentials to perform a database dump

```bash
✗ python3.11 firebirdBrute.py -host x.x.x.x -wordlist common-tables.txt 
This tool attempts to brute force the database names on the Firebird database server using the default credentials (sysdba|masterkey)
[*] Checking credentials (sysdba/masterkey) against x.x.x.x
[+] Credentials ACCEPTED
[*] Bruteforcing 3354 database name(s)

[NOT FOUND] users
[NOT FOUND] customer
[NOT FOUND] user
[NOT FOUND] orders
[...snip...]
```

