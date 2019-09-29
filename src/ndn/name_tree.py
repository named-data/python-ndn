from pygtrie import Trie


class NameTrie(Trie):
    def _path_from_key(self, key):
        # bytes(x) will copy x if x is memoryview or bytearray but will not copy bytes
        return [x if isinstance(x, memoryview) and x.readonly else bytes(x)
                for x in key]

    def _key_from_path(self, path):
        return path
