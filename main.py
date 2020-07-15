import re

import pefile
from arc4 import ARC4
from requests import get

ALPHABET = 'abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ01234567890./='
URL_REGEX = r'((http|https)\:\/\/)?[a-zA-Z0-9\.\/\?\:@\-_=#]+\.([a-zA-Z]){2,6}([a-zA-Z0-9\.\&\/\?\:@\-_=#])*'


class CruLoaderDecoder:
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
    def get_payload_embedded_url(file_path):
        with open(file_path, 'rb') as g:
            data = g.read()

        data = data[data.index(b'cruloader'):data.index(b'aaaaaaaaaaaaaaaa')]

        for i in range(0, len(data) - 4):
            key = set([((a << 4) & 0xFF) + ((a >> 4) & 0xFF) ^ b for a, b in zip(data[i: i + 4], b'http')])

            if len(key) == 1:
                key = key.pop()
                string = ''.join(chr(((char << 4) & 0xFF) + ((char >> 4) & 0xFF) ^ key) for char in data[i:])
                match = re.match(URL_REGEX, string)

                if match:
                    return string[match.start():match.end()]

    @staticmethod
    def __extract_payload(image_buffer):
        pe = image_buffer[image_buffer.index(b'cruloader'[::-1]) + 9:]
        key = pe[0] ^ ord('M')

        buffer = bytearray()
        for char in pe:
            buffer.append(char ^ key)
        return buffer

    def get_decrypted_resource(self):
        data = self.__get_resource()
        return self.decrypt(data[0x0C:0x1B], data[0x1C:])

    def get_payload(self, url):
        try:
            final_url = get(url).text
            r = get(final_url)
            r.raise_for_status()
            return final_url, self.__extract_payload(r.content)
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
    print('[1] Packer Strings\n')
    for word in strings:
        print(f'\t{word} -> {CruLoaderDecoder.rot_13(word)}')

    # Extract resource
    print('\n[2] Extracting Cruloader')
    analyzer = CruLoaderDecoder('main_bin.bin')
    pe_resource = analyzer.get_decrypted_resource()

    with open('cruloader.bin', 'wb') as f:
        f.write(pe_resource)

    # Layer 2
    # Extract URL
    print('\n[3] Finding embedded URL\n')
    first_url = analyzer.get_payload_embedded_url('cruloader.bin')
    print(f'\t{first_url}')

    # Download and extract payload
    print('\n[4] Downloading Payload\n')
    second_url, payload = analyzer.get_payload(first_url)
    print(f'\t{second_url}')

    with open('payload.bin', 'wb') as f:
        f.write(payload)
