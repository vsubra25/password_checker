import requests
import hashlib
import sys


def request_api_data(query_char):
    url = 'https://api.pwnedpasswords.com/range/' + query_char
    res = requests.get(url)
    if res.status_code != 200:
        raise requests.RequestException('Request failed')
    return res


def get_pwd_leaks_count(hashes, hash_to_check):
    hashes = (line.split(':') for line in hashes.text.splitlines())
    for h, count in hashes:
        if h == hash_to_check:
            return count
    return 0


def pwned_api_check(password):
    sha1password = hashlib.sha1(password.encode('utf-8')).hexdigest().upper()
    first5, tail = sha1password[:5], sha1password[5:]
    response = request_api_data(first5)
    return get_pwd_leaks_count(response, tail)


def main(args):
    for password in args:
        count = pwned_api_check(password)
        print(count)
        if count:
            print(
                f'{password} was found {count} times...you should probably think of something else')
        else:
            print(f'{password} was NOT found, continue')
    return 'done!'


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
