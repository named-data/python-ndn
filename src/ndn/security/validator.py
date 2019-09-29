import abc


class Validator:
    @abc.abstractmethod
    async def interest_validate(self):
        pass

    @abc.abstractmethod
    async def data_validate(self):
        pass
