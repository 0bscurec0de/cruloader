import re

import pefile
from arc4 import ARC4
from requests import get

ALPHABET = 'abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ01234567890./='
URL_REGEX = r'((http|https)\:\/\/)?[a-zA-Z0-9\.\/\?\:@\-_=#]+\.([a-zA-Z]){2,6}([a-zA-Z0-9\.\&\/\?\:@\-_=#])*'


class Zero2Auto:
    def __init__(self, file_path):
        self.pe = pefile.PE(file_path)

    @staticmethod
    def decrypt(key, data):
        return ARC4(key).decrypt(data)

    @staticmethod
    def rot_13(cipher):
        return ''.join([ALPHABET[(ALPHABET.index(char) + 0xD) % len(ALPHABET)] for char in cipher])

    def __get_resource(self):
        for resource_type in self.pe.DIRECTORY_ENTRY_RESOURCE.entries:
            for resource_id in resource_type.directory.entries:
                return self.pe.get_data(
                    resource_id.directory.entries[0].data.struct.OffsetToData,
                    resource_id.directory.entries[0].data.struct.Size
                )

    @staticmethod
    def get_embedded_urls(file_path):
        with open(file_path, 'rb') as f:
            data = f.read()

        data = data[data.index(b'cruloader'):data.index(b'aaaaaaaaaaaaaaaa')]

        for i in range(0, len(data) - 4):
            key = set([((a << 4) & 0xFF) + ((a >> 4) & 0xFF) ^ b for a, b in zip(data[i: i + 4], b'http')])

            if len(key) == 1:
                key = key.pop()
                string = ''.join(chr(((char << 4) & 0xFF) + ((char >> 4) & 0xFF) ^ key) for char in data[i:])
                url = re.match(URL_REGEX, string)

                if url:
                    return string[url.start():url.end()]

    @staticmethod
    def __extract_payload(image_buffer):
        pe = image_buffer[image_buffer.index(b'cruloader'[::-1]) + 9:]
        key = pe[0] ^ ord('M')

        payload = bytearray()
        for char in pe:
            payload.append(char ^ key)
        return payload

    def get_decrypted_resource(self):
        data = self.__get_resource()
        clean = self.decrypt(data[0x0C:0x1B], data[0x1C:])

        with open('cruloader.bin', 'wb') as f:
            f.write(clean)

    def get_payload(self, url):
        try:
            final_url = get(url).text

            r = get(final_url)
            r.raise_for_status()

            with open('payload.bin', 'wb') as f:
                f.write(self.__extract_payload(r.content))

            return final_url
        except:
            pass


if __name__ == '__main__':
    # Layer 1
    strings = [
        'F5gG8e514pbag5kg', '.5ea5/QPY4//', 'pe51g5Ceb35ffn', 'I9egh1/n//b3rk', 'E5fh=5G8e514', 'Je9g5Ceb35ffz5=bel',
        'I9egh1/n//b3', 'E514Ceb35ffz5=bel', 't5gG8e514pbag5kg', '.5ea5/QPY4//', 'F9m5b6E5fbhe35', 's9a4E5fbhe35n',
        'I9egh1/n//b3', 'yb3.E5fbhe35', 'yb14E5fbhe35'
    ]

    # Decode strings
    for word in strings:
        print(f'{word} {Zero2Auto.rot_13(word)}')

    # Extract resource
    analyzer = Zero2Auto('main_bin.bin')
    analyzer.get_decrypted_resource()

    # Layer 2
    # Extract URL
    url = analyzer.get_embedded_urls('cruloader.bin')
    print(url)

    # Download and extract payload
    final_url = analyzer.get_payload(url)
    print(final_url)
