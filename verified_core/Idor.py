import sys
from typing import Callable, Any, TypeVar, NamedTuple
from math import floor
from itertools import count

import module_ as module_
import _dafny as _dafny
import System_ as System_
import PathTrav as PathTrav
import Redirect as Redirect

# Module: Idor

class default__:
    def  __init__(self):
        pass

    @staticmethod
    def OwnerOnly(session, value):
        allowed: bool = False
        if (session).is_None:
            allowed = False
            return allowed
        if ((session).v) != (value):
            allowed = False
            return allowed
        allowed = True
        return allowed
        return allowed


class Opt:
    @classmethod
    def default(cls, ):
        return lambda: Opt_None()
    def __ne__(self, __o: object) -> bool:
        return not self.__eq__(__o)
    @property
    def is_None(self) -> bool:
        return isinstance(self, Opt_None)
    @property
    def is_Some(self) -> bool:
        return isinstance(self, Opt_Some)

class Opt_None(Opt, NamedTuple('None_', [])):
    def __dafnystr__(self) -> str:
        return f'Idor.Opt.None'
    def __eq__(self, __o: object) -> bool:
        return isinstance(__o, Opt_None)
    def __hash__(self) -> int:
        return super().__hash__()

class Opt_Some(Opt, NamedTuple('Some', [('v', Any)])):
    def __dafnystr__(self) -> str:
        return f'Idor.Opt.Some({self.v.VerbatimString(True)})'
    def __eq__(self, __o: object) -> bool:
        return isinstance(__o, Opt_Some) and self.v == __o.v
    def __hash__(self) -> int:
        return super().__hash__()

