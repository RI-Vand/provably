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
import StateMachine as StateMachine
import Ledger as Ledger

# Module: SingleUse

class default__:
    def  __init__(self):
        pass

    @staticmethod
    def Consume(used, token):
        ok: bool = False
        used2: _dafny.Set = _dafny.Set({})
        if (token) in (used):
            rhs0_ = False
            rhs1_ = used
            ok = rhs0_
            used2 = rhs1_
            return ok, used2
        rhs2_ = True
        rhs3_ = (used) | (_dafny.Set({token}))
        ok = rhs2_
        used2 = rhs3_
        return ok, used2
        return ok, used2

