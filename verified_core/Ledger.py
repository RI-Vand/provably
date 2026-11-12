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

# Module: Ledger

class default__:
    def  __init__(self):
        pass

    @staticmethod
    def TransferPlan(srcBal, dstBal, amt, maxAmt, sameAccount):
        ok: bool = False
        newSrc: int = int(0)
        newDst: int = int(0)
        if (((sameAccount) or ((amt) <= (0))) or ((amt) > (maxAmt))) or ((amt) > (srcBal)):
            rhs0_ = False
            rhs1_ = srcBal
            rhs2_ = dstBal
            ok = rhs0_
            newSrc = rhs1_
            newDst = rhs2_
            return ok, newSrc, newDst
        rhs3_ = True
        rhs4_ = (srcBal) - (amt)
        rhs5_ = (dstBal) + (amt)
        ok = rhs3_
        newSrc = rhs4_
        newDst = rhs5_
        return ok, newSrc, newDst
        return ok, newSrc, newDst

