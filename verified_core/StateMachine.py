import sys
from typing import Callable, Any, TypeVar, NamedTuple
from math import floor
from itertools import count

import module_ as module_
import _dafny as _dafny
import System_ as System_
import PathTrav as PathTrav
import Redirect as Redirect
import Idor as Idor
import Cmdi as Cmdi
import StrictParams as StrictParams
import RateLimit as RateLimit
import Authz as Authz

# Module: StateMachine

class default__:
    def  __init__(self):
        pass

    @staticmethod
    def Transition(edges, cur, nxt):
        ok: bool = False
        if (Edge_Edge(cur, nxt)) in (edges):
            ok = True
            return ok
        ok = False
        return ok
        return ok


class Edge:
    @classmethod
    def default(cls, ):
        return lambda: Edge_Edge(_dafny.SeqWithoutIsStrInference(map(_dafny.CodePoint, "")), _dafny.SeqWithoutIsStrInference(map(_dafny.CodePoint, "")))
    def __ne__(self, __o: object) -> bool:
        return not self.__eq__(__o)
    @property
    def is_Edge(self) -> bool:
        return isinstance(self, Edge_Edge)

class Edge_Edge(Edge, NamedTuple('Edge', [('from_', Any), ('to', Any)])):
    def __dafnystr__(self) -> str:
        return f'StateMachine.Edge.Edge({self.from_.VerbatimString(True)}, {self.to.VerbatimString(True)})'
    def __eq__(self, __o: object) -> bool:
        return isinstance(__o, Edge_Edge) and self.from_ == __o.from_ and self.to == __o.to
    def __hash__(self) -> int:
        return super().__hash__()

