class BaseRepo:
    def save(self, item):
        return self._write(item)

    def _write(self, item):
        return item
