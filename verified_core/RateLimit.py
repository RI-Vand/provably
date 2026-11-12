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

# Module: RateLimit

class default__:
    def  __init__(self):
        pass

    @staticmethod
    def Count(acc, now, w):
        d_0___accumulator_ = 0
        while True:
            with _dafny.label():
                if (len(acc)) == (0):
                    return (0) + (d_0___accumulator_)
                elif True:
                    d_0___accumulator_ = (d_0___accumulator_) + ((1 if ((now) - ((acc)[(len(acc)) - (1)])) < (w) else 0))
                    in0_ = _dafny.SeqWithoutIsStrInference((acc)[:(len(acc)) - (1):])
                    in1_ = now
                    in2_ = w
                    acc = in0_
                    now = in1_
                    w = in2_
                    raise _dafny.TailCall()
                break

    @staticmethod
    def Sorted(a):
        def lambda0_(forall_var_0_):
            def lambda1_(forall_var_1_):
                d_1_j_: int = forall_var_1_
                return not ((((0) <= (d_0_i_)) and ((d_0_i_) < (d_1_j_))) and ((d_1_j_) < (len(a)))) or (((a)[d_0_i_]) <= ((a)[d_1_j_]))

            d_0_i_: int = forall_var_0_
            return _dafny.quantifier(_dafny.IntegerRange((d_0_i_) + (1), len(a)), True, lambda1_)

        return _dafny.quantifier(_dafny.IntegerRange(0, len(a)), True, lambda0_)

    @staticmethod
    def Valid(acc, limit, w):
        def lambda0_(forall_var_0_):
            d_0_i_: int = forall_var_0_
            return not (((0) <= (d_0_i_)) and ((d_0_i_) < (len(acc)))) or ((default__.Count(_dafny.SeqWithoutIsStrInference((acc)[:(d_0_i_) + (1):]), (acc)[d_0_i_], w)) <= (limit))

        return (default__.Sorted(acc)) and (_dafny.quantifier(_dafny.IntegerRange(0, len(acc)), True, lambda0_))

    @staticmethod
    def Allow(acc, now, limit, w):
        ok: bool = False
        acc2: _dafny.Seq = _dafny.Seq({})
        if (default__.Count(acc, now, w)) < (limit):
            acc2 = (acc) + (_dafny.SeqWithoutIsStrInference([now]))
            rhs0_ = True
            rhs1_ = acc2
            ok = rhs0_
            acc2 = rhs1_
            return ok, acc2
        rhs2_ = False
        rhs3_ = acc
        ok = rhs2_
        acc2 = rhs3_
        return ok, acc2
        return ok, acc2

