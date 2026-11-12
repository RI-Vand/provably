import sys
from typing import Callable, Any, TypeVar, NamedTuple
from math import floor
from itertools import count

import module_ as module_
import _dafny as _dafny
import System_ as System_

# Module: PathTrav

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
    def WellFormed(g):
        return not ((g).is_Name) or (((((g).s) != (_dafny.SeqWithoutIsStrInference(map(_dafny.CodePoint, "")))) and (((g).s) != (_dafny.SeqWithoutIsStrInference(map(_dafny.CodePoint, "."))))) and (((g).s) != (_dafny.SeqWithoutIsStrInference(map(_dafny.CodePoint, "..")))))

    @staticmethod
    def Canonical(p):
        def lambda0_(forall_var_0_):
            d_0_i_: int = forall_var_0_
            return not (((0) <= (d_0_i_)) and ((d_0_i_) < (len(p)))) or (((((p)[d_0_i_]) != (_dafny.SeqWithoutIsStrInference(map(_dafny.CodePoint, "")))) and (((p)[d_0_i_]) != (_dafny.SeqWithoutIsStrInference(map(_dafny.CodePoint, "."))))) and (((p)[d_0_i_]) != (_dafny.SeqWithoutIsStrInference(map(_dafny.CodePoint, "..")))))

        return _dafny.quantifier(_dafny.IntegerRange(0, len(p)), True, lambda0_)

    @staticmethod
    def IsPrefix(p, s):
        return ((len(p)) <= (len(s))) and ((_dafny.SeqWithoutIsStrInference((s)[:len(p):])) == (p))

    @staticmethod
    def NulSeg(g):
        return ((g).is_Name) and (default__.HasNul((g).s))

    @staticmethod
    def Names(gs):
        d_0___accumulator_ = _dafny.SeqWithoutIsStrInference([])
        while True:
            with _dafny.label():
                if (len(gs)) == (0):
                    return (_dafny.SeqWithoutIsStrInference([])) + (d_0___accumulator_)
                elif True:
                    d_0___accumulator_ = (_dafny.SeqWithoutIsStrInference([((gs)[(len(gs)) - (1)]).s])) + (d_0___accumulator_)
                    in0_ = _dafny.SeqWithoutIsStrInference((gs)[:(len(gs)) - (1):])
                    gs = in0_
                    raise _dafny.TailCall()
                break

    @staticmethod
    def SafeJoin(base, names):
        ok: bool = False
        result: _dafny.Seq = _dafny.Seq({})
        d_0_stack_: _dafny.Seq
        d_0_stack_ = base
        d_1_i_: int
        d_1_i_ = 0
        while (d_1_i_) < (len(names)):
            source0_ = (names)[d_1_i_]
            with _dafny.label("match0"):
                if True:
                    if source0_.is_Name:
                        d_2_s_ = source0_.s
                        if default__.HasNul(d_2_s_):
                            rhs0_ = False
                            rhs1_ = _dafny.SeqWithoutIsStrInference([])
                            ok = rhs0_
                            result = rhs1_
                            return ok, result
                        d_0_stack_ = (d_0_stack_) + (_dafny.SeqWithoutIsStrInference([d_2_s_]))
                        raise _dafny.Break("match0")
                if True:
                    if source0_.is_Cur:
                        pass
                        raise _dafny.Break("match0")
                if True:
                    if source0_.is_Up:
                        if (len(d_0_stack_)) > (0):
                            d_0_stack_ = _dafny.SeqWithoutIsStrInference((d_0_stack_)[:(len(d_0_stack_)) - (1):])
                        raise _dafny.Break("match0")
                if True:
                    d_0_stack_ = _dafny.SeqWithoutIsStrInference([])
                pass
            d_1_i_ = (d_1_i_) + (1)
        if default__.IsPrefix(base, d_0_stack_):
            rhs2_ = True
            rhs3_ = d_0_stack_
            ok = rhs2_
            result = rhs3_
            return ok, result
        rhs4_ = False
        rhs5_ = _dafny.SeqWithoutIsStrInference([])
        ok = rhs4_
        result = rhs5_
        return ok, result
        return ok, result

    @staticmethod
    def Contained(base, p):
        b: bool = False
        if (len(base)) > (len(p)):
            b = False
            return b
        if (_dafny.SeqWithoutIsStrInference((p)[:len(base):])) == (base):
            b = True
            return b
        b = False
        return b
        return b


class Seg:
    @classmethod
    def default(cls, ):
        return lambda: Seg_Name(_dafny.SeqWithoutIsStrInference(map(_dafny.CodePoint, "")))
    def __ne__(self, __o: object) -> bool:
        return not self.__eq__(__o)
    @property
    def is_Name(self) -> bool:
        return isinstance(self, Seg_Name)
    @property
    def is_Up(self) -> bool:
        return isinstance(self, Seg_Up)
    @property
    def is_Cur(self) -> bool:
        return isinstance(self, Seg_Cur)
    @property
    def is_Root(self) -> bool:
        return isinstance(self, Seg_Root)

class Seg_Name(Seg, NamedTuple('Name', [('s', Any)])):
    def __dafnystr__(self) -> str:
        return f'PathTrav.Seg.Name({self.s.VerbatimString(True)})'
    def __eq__(self, __o: object) -> bool:
        return isinstance(__o, Seg_Name) and self.s == __o.s
    def __hash__(self) -> int:
        return super().__hash__()

class Seg_Up(Seg, NamedTuple('Up', [])):
    def __dafnystr__(self) -> str:
        return f'PathTrav.Seg.Up'
    def __eq__(self, __o: object) -> bool:
        return isinstance(__o, Seg_Up)
    def __hash__(self) -> int:
        return super().__hash__()

class Seg_Cur(Seg, NamedTuple('Cur', [])):
    def __dafnystr__(self) -> str:
        return f'PathTrav.Seg.Cur'
    def __eq__(self, __o: object) -> bool:
        return isinstance(__o, Seg_Cur)
    def __hash__(self) -> int:
        return super().__hash__()

class Seg_Root(Seg, NamedTuple('Root', [])):
    def __dafnystr__(self) -> str:
        return f'PathTrav.Seg.Root'
    def __eq__(self, __o: object) -> bool:
        return isinstance(__o, Seg_Root)
    def __hash__(self) -> int:
        return super().__hash__()

