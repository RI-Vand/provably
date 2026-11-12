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

# Module: StrictParams

class default__:
    def  __init__(self):
        pass

    @staticmethod
    def Check(fields, allowed, benign, maxLen, longest):
        ok: bool = False
        if not((fields).issubset((allowed) | (benign))):
            ok = False
            return ok
        if (longest) > (maxLen):
            ok = False
            return ok
        ok = True
        return ok
        return ok

