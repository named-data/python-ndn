# TODO: Change these names
from .schema_tree import Node


class LocalResource(Node):
    def __init__(self, parent=None, data=None):
        super().__init__(parent)
        self.data = data

    async def on_register(self, root, app, prefix, cached: bool):
        self.prefix = prefix
        self.app = app
        return await app.register(prefix, root._on_interest_root, root._int_validator, True)

    async def need(self, match, **kwargs):
        return self.data

    async def provide(self, match, content, **kwargs):
        self.data = content
