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

# Module: Authz

class default__:
    def  __init__(self):
        pass

    @staticmethod
    def Authorize(policy, role, action):
        ok: bool = False
        if (Rule_Rule(role, action)) in (policy):
            ok = True
            return ok
        ok = False
        return ok
        return ok


class Rule:
    @classmethod
    def default(cls, ):
        return lambda: Rule_Rule(_dafny.SeqWithoutIsStrInference(map(_dafny.CodePoint, "")), _dafny.SeqWithoutIsStrInference(map(_dafny.CodePoint, "")))
    def __ne__(self, __o: object) -> bool:
        return not self.__eq__(__o)
    @property
    def is_Rule(self) -> bool:
        return isinstance(self, Rule_Rule)

class Rule_Rule(Rule, NamedTuple('Rule', [('role', Any), ('action', Any)])):
    def __dafnystr__(self) -> str:
        return f'Authz.Rule.Rule({self.role.VerbatimString(True)}, {self.action.VerbatimString(True)})'
    def __eq__(self, __o: object) -> bool:
        return isinstance(__o, Rule_Rule) and self.role == __o.role and self.action == __o.action
    def __hash__(self) -> int:
        return super().__hash__()

