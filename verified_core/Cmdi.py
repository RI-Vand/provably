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

# Module: Cmdi

class default__:
    def  __init__(self):
        pass

    @staticmethod
    def HasNul(s):
        def lambda0_(exists_var_0_):
            d_0_i_: int = exists_var_0_
            return (((0) <= (d_0_i_)) and ((d_0_i_) < (len(s)))) and (((s)[d_0_i_]) == (_dafny.CodePoint('\u0000')))

        return _dafny.quantifier(_dafny.IntegerRange(0, len(s)), False, lambda0_)

    @staticmethod
    def SafeArg(v):
        ok: bool = False
        if ((len(v)) > (0)) and (((v)[0]) == (_dafny.CodePoint('-'))):
            ok = False
            return ok
        if default__.HasNul(v):
            ok = False
            return ok
        ok = True
        return ok
        return ok

