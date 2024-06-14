from copy import copy
from json import dumps


class ENTITYTYPE:
    FILE = 1
    PROCESS = 2
    SOCKET = 3
    entity_type_map = {1: "File", 2: "Process", 3: "Socket"}


class BaseLog:
    category = 0

    class Entity:
        def __init__(self):
            self.entity_type = ENTITYTYPE.FILE
            self.entity_name = None  # 一般是进程号
            self.entity_data = None  # 一般是进程名称

    def __init__(self):
        self.Timestamp = None
        self.object = self.Entity()
        self.subject = self.Entity()
        self.action = None
        self.payload = None
        self.label = None
        self.log = None

    def __lt__(self, other):
        return self.Timestamp <= other.Timestamp

    def to__dict(self):
        a = copy(self.__dict__)
        del a['object']
        del a['subject']
        del a['log']
        #return dumps(a)
        return a

    @property
    def _has_timestamp(self):
        if self.Timestamp is None:
            return False
        return True

if __name__ == '__main__':
    b = BaseLog()
    print(b)
